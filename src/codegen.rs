// src/codegen.rs
//
// Deterministic code generation for v0.5.x lifecycle verifier.

use crate::ast::*;
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn build_project(
    program: &Program,
    build_dir: &Path,
    codegen_hash: [u8; 32],
    source_hash: [u8; 32],
    policy_hash: [u8; 32],
    agent_id: u32,
) -> Result<()> {
    if build_dir.exists() {
        fs::remove_dir_all(build_dir)?;
    }

    fs::create_dir_all(build_dir.join("src"))?;
    fs::create_dir_all(build_dir.join("src/runtime"))?;

    copy_runtime(build_dir)?;

    let main_rs = generate_main(program, codegen_hash, source_hash, policy_hash, agent_id);
    fs::write(build_dir.join("src/main.rs"), main_rs)?;

    fs::write(
        build_dir.join("Cargo.toml"),
        r#"[package]
name = "nex_out"
version = "0.1.0"
edition = "2021"

[features]
coop_scheduler = []

[dependencies]
sha2 = "0.10"
hex = "0.4"
rand = "0.8"
base64 = "0.22"
ed25519-dalek = "2"
"#,
    )?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--offline");
    if cfg!(feature = "coop_scheduler") {
        cmd.arg("--features").arg("coop_scheduler");
    }

    let output = cmd
        .current_dir(build_dir)
        .output()
        .with_context(|| format!("Failed to run cargo build in {}", build_dir.display()))?;

    if !output.status.success() {
        return Err(anyhow!(
            "Generated crate build failed in {}\nstatus: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            build_dir.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

pub fn compute_codegen_hash(
    program: &Program,
    source_hash: [u8; 32],
    policy_hash: [u8; 32],
    agent_id: u32,
) -> [u8; 32] {
    let canonical = generate_main(program, [0u8; 32], source_hash, policy_hash, agent_id);
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

fn copy_runtime(build_dir: &Path) -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let runtime_src = root.join("src/runtime");

    for entry in fs::read_dir(runtime_src)? {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            let name = p
                .file_name()
                .ok_or_else(|| anyhow!("runtime source missing file name: {}", p.display()))?;
            fs::copy(&p, build_dir.join("src/runtime").join(name))?;
        }
    }

    Ok(())
}

fn generate_main(
    program: &Program,
    codegen_hash: [u8; 32],
    source_hash: [u8; 32],
    policy_hash: [u8; 32],
    agent_id: u32,
) -> String {
    let mut s = String::new();

    s.push_str("use std::collections::{BTreeMap, BTreeSet, VecDeque};\n");
    s.push_str("use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};\n");
    s.push_str("use std::sync::{Arc, Mutex};\n");
    if !cfg!(feature = "coop_scheduler") {
        s.push_str("use std::thread::JoinHandle;\n");
    }
    s.push_str("\n");

    s.push_str("mod runtime;\n");
    s.push_str("use runtime::backend::{BackendKind, ExecBackend};\n");
    s.push_str("use runtime::event_recorder::{init_global_recorder_with_jsonl, recorder};\n\n");
    s.push_str("use runtime::io_proxy::{DefaultIoProxy, IoError, IoProxy};\nuse runtime::agent_bus::{Mailbox, Message};\n\n");

    s.push_str("const CANCEL_REASON_BFS_SUBTREE: u32 = 1;\n");
    s.push_str(&format!(
        "const COOP_MODE: bool = {};\n\n",
        if cfg!(feature = "coop_scheduler") {
            "true"
        } else {
            "false"
        }
    ));

    s.push_str("struct TaskEntry {\n");
    s.push_str("    parent: Option<u64>,\n");
    s.push_str("    children: BTreeSet<u64>,\n");
    s.push_str("    cancel: Arc<AtomicBool>,\n");
    if !cfg!(feature = "coop_scheduler") {
        s.push_str("    handle: Option<JoinHandle<i32>>,\n");
    }
    s.push_str("    started: bool,\n");
    s.push_str("    finished: bool,\n");
    s.push_str("    joined: bool,\n");
    s.push_str("    cancelled_emitted: bool,\n");
    s.push_str("}\n\n");

    s.push_str("impl TaskEntry {\n");
    s.push_str("    fn new(parent: Option<u64>, cancel: Arc<AtomicBool>) -> Self {\n");
    s.push_str("        Self {\n");
    s.push_str("            parent,\n");
    s.push_str("            children: BTreeSet::new(),\n");
    s.push_str("            cancel,\n");
    if !cfg!(feature = "coop_scheduler") {
        s.push_str("            handle: None,\n");
    }
    s.push_str("            started: false,\n");
    s.push_str("            finished: false,\n");
    s.push_str("            joined: false,\n");
    s.push_str("            cancelled_emitted: false,\n");
    s.push_str("        }\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    s.push_str("struct Runtime {\n");
    s.push_str("    tasks: Mutex<BTreeMap<u64, TaskEntry>>,\n");
    s.push_str("    next_task_id: AtomicU64,\n");
    s.push_str(
        "    coop_jobs: Mutex<BTreeMap<u64, Box<dyn FnOnce(&Runtime, u64) -> i32 + Send + 'static>>>,\n",
    );
    s.push_str("    backend: Mutex<BackendKind>,\n");
    s.push_str("    mailbox: Mutex<Mailbox>,\n");
    s.push_str("    io: Mutex<Box<dyn IoProxy + Send>>,\n");
    s.push_str("}\n\n");

    s.push_str("impl Runtime {\n");
    s.push_str("    fn new() -> Self {\n");
    s.push_str("        let mut tasks = BTreeMap::new();\n");
    s.push_str(
        "        tasks.insert(0, TaskEntry::new(None, Arc::new(AtomicBool::new(false))));\n",
    );
    s.push_str("        Self {\n");
    s.push_str("            tasks: Mutex::new(tasks),\n");
    s.push_str("            next_task_id: AtomicU64::new(1),\n");
    s.push_str("            coop_jobs: Mutex::new(BTreeMap::new()),\n");
    s.push_str("            backend: Mutex::new(BackendKind::new()),\n");
    s.push_str("            mailbox: Mutex::new(Mailbox::new()),\n");
    s.push_str("            io: Mutex::new(Box::new(DefaultIoProxy::new())),\n");
    s.push_str("        }\n");
    s.push_str("    }\n\n");

    s.push_str("    fn fs_read(&self, path: &str) -> Result<Vec<u8>, IoError> {\n");
    s.push_str("        let mut io = self.io.lock().unwrap();\n");
    s.push_str("        io.fs_read(path)\n");
    s.push_str("    }\n\n");

    s.push_str("    fn fs_write(&self, path: &str, data: &[u8]) -> Result<(), IoError> {\n");
    s.push_str("        let mut io = self.io.lock().unwrap();\n");
    s.push_str("        io.fs_write(path, data)\n");
    s.push_str("    }\n\n");

    s.push_str(
        "    fn bus_send(&self, sender: u32, receiver: u32, seq: u64, kind: u16) -> u64 {\n",
    );
    s.push_str("        let outcome = {\n");
    s.push_str("            let mut mailbox = self.mailbox.lock().unwrap();\n");
    s.push_str("            mailbox.send(\n");
    s.push_str("                sender,\n");
    s.push_str("                receiver,\n");
    s.push_str("                Message {\n");
    s.push_str("                    req_id: 0,\n");
    s.push_str("                    channel_id: 0,\n");
    s.push_str("                    sender,\n");
    s.push_str("                    sender_seq: seq,\n");
    s.push_str("                    seq,\n");
    s.push_str("                    kind,\n");
    s.push_str("                    schema_id: 0,\n");
    s.push_str("                    payload: Vec::new(),\n");
    s.push_str("                },\n");
    s.push_str("            )\n");
    s.push_str("        };\n");
    s.push_str("\n");
    s.push_str("        if let Ok(mut rec) = recorder().lock() {\n");
    s.push_str(
        "            let _ = rec.record_bus_send_request(0, outcome.req_id, sender, receiver, 0, outcome.bytes);\n",
    );
    s.push_str(
        "            let _ = rec.record_bus_decision(0, outcome.req_id, outcome.allowed, outcome.reason_code);\n",
    );
    s.push_str("            if outcome.fuel_cost > 0 {\n");
    s.push_str(
        "                let _ = rec.record_fuel_debit(0, 0, 0, outcome.fuel_cost, runtime::event::FuelReason::ProxyCall);\n",
    );
    s.push_str("            }\n");
    s.push_str("            let _ = rec.record_bus_send_result(0, outcome.req_id, outcome.ok);\n");
    s.push_str("            if outcome.ok {\n");
    s.push_str(
        "                let _ = rec.record_bus_send(0, outcome.req_id, sender, receiver, kind, 0, 0);\n",
    );
    s.push_str("            }\n");
    s.push_str("        }\n");
    s.push_str("\n");
    s.push_str("        if outcome.ok && COOP_MODE {\n");
    s.push_str("            let _ = self.backend_wake_recv_waiters(receiver);\n");
    s.push_str("        }\n");
    s.push_str("\n");
    s.push_str("        outcome.req_id\n");
    s.push_str("    }\n\n");

    s.push_str("    fn bus_recv(&self, task: u64, receiver: u32) -> Option<Message> {\n");
    s.push_str("        let outcome = {\n");
    s.push_str("            let mut mailbox = self.mailbox.lock().unwrap();\n");
    s.push_str("            mailbox.recv(receiver)\n");
    s.push_str("        };\n");
    s.push_str("\n");
    s.push_str("        if !outcome.allowed {\n");
    s.push_str("            if let Ok(mut rec) = recorder().lock() {\n");
    s.push_str(
        "                let _ = rec.record_bus_decision(0, 0, false, outcome.reason_code);\n",
    );
    s.push_str("            }\n");
    s.push_str("            return None;\n");
    s.push_str("        }\n");
    s.push_str("\n");
    s.push_str("        let msg = outcome.message;\n");
    s.push_str("\n");
    s.push_str("        if let Some(m) = msg.as_ref() {\n");
    s.push_str("            if let Ok(mut rec) = recorder().lock() {\n");
    s.push_str("                let _ = rec.record_bus_recv(0, m.req_id, receiver);\n");
    s.push_str("            }\n");
    s.push_str("        }\n");
    s.push_str("\n");
    s.push_str("        if msg.is_none() && COOP_MODE {\n");
    s.push_str("            self.backend_block_on_recv(task, receiver);\n");
    s.push_str("        }\n");
    s.push_str("\n");
    s.push_str("        msg\n");
    s.push_str("    }\n\n");

    s.push_str("    fn backend_spawn(&self, parent: u64) -> u64 {\n");
    s.push_str("        let mut backend = self.backend.lock().unwrap();\n");
    s.push_str("        backend.spawn(parent)\n");
    s.push_str("    }\n\n");

    s.push_str("    fn backend_request_join(&self, waiter: u64, target: u64) {\n");
    s.push_str("        let mut backend = self.backend.lock().unwrap();\n");
    s.push_str("        backend.request_join(waiter, target);\n");
    s.push_str("    }\n\n");

    s.push_str("    fn backend_block_on_recv(&self, task: u64, agent: u32) {\n");
    s.push_str("        let mut backend = self.backend.lock().unwrap();\n");
    s.push_str("        backend.block_on_recv(task, agent);\n");
    s.push_str("    }\n\n");

    s.push_str("    fn backend_wake_recv_waiters(&self, agent: u32) -> Vec<u64> {\n");
    s.push_str("        let mut backend = self.backend.lock().unwrap();\n");
    s.push_str("        backend.wake_recv_waiters(agent)\n");
    s.push_str("    }\n\n");

    s.push_str("    fn backend_cancel_bfs(&self, root: u64) -> Vec<u64> {\n");
    s.push_str("        let mut backend = self.backend.lock().unwrap();\n");
    s.push_str("        backend.cancel_bfs(root)\n");
    s.push_str("    }\n\n");

    s.push_str("    fn backend_forced_exit_code(&self) -> Option<i32> {\n");
    s.push_str("        let backend = self.backend.lock().unwrap();\n");
    s.push_str("        backend.forced_exit_code()\n");
    s.push_str("    }\n\n");

    s.push_str("    fn backend_tick_or_step(&self) {\n");
    s.push_str("        if COOP_MODE {\n");
    s.push_str("            let mut spins: u64 = 0;\n");
    s.push_str("            loop {\n");
    s.push_str("                let picked = {\n");
    s.push_str("                    let mut backend = self.backend.lock().unwrap();\n");
    s.push_str("                    backend.run();\n");
    s.push_str("                    backend.take_picked()\n");
    s.push_str("                };\n\n");
    s.push_str("                if let Some(task) = picked {\n");
    s.push_str("                    let exit = self.execute_one_coop_task(task);\n");
    s.push_str("                    let mut backend = self.backend.lock().unwrap();\n");
    s.push_str("                    backend.complete(task, exit);\n");
    s.push_str("                } else {\n");
    s.push_str("                    let done = {\n");
    s.push_str("                        let backend = self.backend.lock().unwrap();\n");
    s.push_str("                        backend.is_finished()\n");
    s.push_str("                    };\n");
    s.push_str("                    if done {\n");
    s.push_str("                        break;\n");
    s.push_str("                    }\n");
    s.push_str("                }\n\n");
    s.push_str("                spins = spins.saturating_add(1);\n");
    s.push_str("                if spins > 1_000_000 {\n");
    s.push_str("                    break;\n");
    s.push_str("                }\n");
    s.push_str("            }\n");
    s.push_str("        } else {\n");
    s.push_str("            let mut backend = self.backend.lock().unwrap();\n");
    s.push_str("            backend.tick_or_step();\n");
    s.push_str("        }\n");
    s.push_str("    }\n\n");

    s.push_str("    fn init_root(&self) {\n");
    s.push_str("        {\n");
    s.push_str("            let mut tasks = self.tasks.lock().unwrap();\n");
    s.push_str("            if let Some(root) = tasks.get_mut(&0) {\n");
    s.push_str("                root.started = true;\n");
    s.push_str("            }\n");
    s.push_str("        }\n");
    s.push_str("        self.record_task_started(0);\n");
    s.push_str("    }\n\n");

    s.push_str("    fn finish_root(&self, exit_code: i32) {\n");
    s.push_str("        {\n");
    s.push_str("            let mut tasks = self.tasks.lock().unwrap();\n");
    s.push_str("            if let Some(root) = tasks.get_mut(&0) {\n");
    s.push_str("                root.finished = true;\n");
    s.push_str("            }\n");
    s.push_str("        }\n");
    s.push_str("        self.record_task_finished(0, exit_code);\n");
    s.push_str("    }\n\n");

    s.push_str("    fn record_task_spawned(&self, parent: u64, child: u64) {\n");
    s.push_str("        let mut rec = recorder().lock().unwrap();\n");
    s.push_str("        rec.record_task_spawned(parent, child).unwrap();\n");
    s.push_str("    }\n\n");

    s.push_str("    fn record_task_started(&self, task: u64) {\n");
    s.push_str("        let mut rec = recorder().lock().unwrap();\n");
    s.push_str("        rec.record_task_started(task).unwrap();\n");
    s.push_str("    }\n\n");

    s.push_str("    fn record_task_finished(&self, task: u64, exit: i32) {\n");
    s.push_str("        let mut rec = recorder().lock().unwrap();\n");
    s.push_str("        rec.record_task_finished(task, exit).unwrap();\n");
    s.push_str("    }\n\n");

    s.push_str("    fn record_task_cancelled(&self, task: u64, reason: u32) {\n");
    s.push_str("        let mut rec = recorder().lock().unwrap();\n");
    s.push_str("        rec.record_task_cancelled(task, reason).unwrap();\n");
    s.push_str("    }\n\n");

    s.push_str("    fn record_task_joined(&self, joiner: u64, joined: u64) {\n");
    s.push_str("        let mut rec = recorder().lock().unwrap();\n");
    s.push_str("        rec.record_task_joined(joiner, joined).unwrap();\n");
    s.push_str("    }\n\n");

    s.push_str("    fn mark_task_finished(&self, task: u64) {\n");
    s.push_str("        let mut tasks = self.tasks.lock().unwrap();\n");
    s.push_str("        if let Some(entry) = tasks.get_mut(&task) {\n");
    s.push_str("            entry.finished = true;\n");
    s.push_str("        }\n");
    s.push_str("    }\n\n");

    s.push_str("    fn is_task_finished(&self, task: u64) -> bool {\n");
    s.push_str("        let tasks = self.tasks.lock().unwrap();\n");
    s.push_str("        tasks.get(&task).map(|entry| entry.finished).unwrap_or(false)\n");
    s.push_str("    }\n\n");

    s.push_str("    fn execute_one_coop_task(&self, task: u64) -> i32 {\n");
    s.push_str("        if task == 0 {\n");
    s.push_str("            return 0;\n");
    s.push_str("        }\n");
    s.push_str("        let job = {\n");
    s.push_str("            let mut jobs = self.coop_jobs.lock().unwrap();\n");
    s.push_str("            jobs.remove(&task)\n");
    s.push_str("        };\n");
    s.push_str("        let Some(job) = job else {\n");
    s.push_str("            return 0;\n");
    s.push_str("        };\n\n");
    s.push_str("        self.record_task_started(task);\n");
    s.push_str("        {\n");
    s.push_str("            let mut tasks = self.tasks.lock().unwrap();\n");
    s.push_str("            if let Some(entry) = tasks.get_mut(&task) {\n");
    s.push_str("                entry.started = true;\n");
    s.push_str("            }\n");
    s.push_str("        }\n\n");
    s.push_str("        let exit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {\n");
    s.push_str("            job(self, task)\n");
    s.push_str("        }))\n");
    s.push_str("        .unwrap_or(1);\n\n");
    s.push_str("        self.mark_task_finished(task);\n");
    s.push_str("        self.record_task_finished(task, exit);\n");
    s.push_str("        exit\n");
    s.push_str("    }\n\n");

    s.push_str("    fn spawn_task<F>(rt: &Arc<Self>, parent: u64, f: F) -> u64\n");
    s.push_str("    where\n");
    s.push_str("        F: FnOnce(Arc<Self>, u64) -> i32 + Send + 'static,\n");
    s.push_str("    {\n");
    s.push_str("        let child = rt.next_task_id.fetch_add(1, Ordering::SeqCst);\n");
    s.push_str("        let _ = rt.backend_spawn(parent);\n");
    s.push_str("        let cancel = Arc::new(AtomicBool::new(false));\n\n");

    s.push_str("        {\n");
    s.push_str("            let mut tasks = rt.tasks.lock().unwrap();\n");
    s.push_str(
        "            tasks.insert(child, TaskEntry::new(Some(parent), Arc::clone(&cancel)));\n",
    );
    s.push_str("            if let Some(parent_entry) = tasks.get_mut(&parent) {\n");
    s.push_str("                parent_entry.children.insert(child);\n");
    s.push_str("            }\n");
    s.push_str("        }\n\n");

    s.push_str("        rt.record_task_spawned(parent, child);\n\n");

    if cfg!(feature = "coop_scheduler") {
        s.push_str("        let rt_for_job = Arc::clone(rt);\n");
        s.push_str("        let mut jobs = rt.coop_jobs.lock().unwrap();\n");
        s.push_str(
            "        jobs.insert(child, Box::new(move |_rt_ref: &Runtime, task_id: u64| -> i32 {\n",
        );
        s.push_str("            f(Arc::clone(&rt_for_job), task_id)\n");
        s.push_str("        }));\n\n");
    } else {
        s.push_str("        let (started_tx, started_rx) = std::sync::mpsc::channel();\n");
        s.push_str("        let rt_child = Arc::clone(rt);\n");
        s.push_str("        let handle = std::thread::spawn(move || {\n");
        s.push_str("            rt_child.record_task_started(child);\n");
        s.push_str("            {\n");
        s.push_str("                let mut tasks = rt_child.tasks.lock().unwrap();\n");
        s.push_str("                if let Some(entry) = tasks.get_mut(&child) {\n");
        s.push_str("                    entry.started = true;\n");
        s.push_str("                }\n");
        s.push_str("            }\n");
        s.push_str("            let _ = started_tx.send(());\n\n");

        s.push_str(
            "            let exit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {\n",
        );
        s.push_str("                f(Arc::clone(&rt_child), child)\n");
        s.push_str("            }))\n");
        s.push_str("            .unwrap_or(1);\n\n");

        s.push_str("            rt_child.mark_task_finished(child);\n");
        s.push_str("            rt_child.record_task_finished(child, exit);\n");
        s.push_str("            exit\n");
        s.push_str("        });\n\n");

        s.push_str("        let _ = started_rx.recv();\n\n");

        s.push_str("        {\n");
        s.push_str("            let mut tasks = rt.tasks.lock().unwrap();\n");
        s.push_str("            if let Some(entry) = tasks.get_mut(&child) {\n");
        s.push_str("                entry.handle = Some(handle);\n");
        s.push_str("            }\n");
        s.push_str("        }\n\n");
    }

    s.push_str("        child\n");
    s.push_str("    }\n\n");

    if cfg!(feature = "coop_scheduler") {
        s.push_str("    fn join_task(&self, joiner: u64, joined: u64) {\n");
        s.push_str("        let mut should_record = false;\n");
        s.push_str("        {\n");
        s.push_str("            let mut tasks = self.tasks.lock().unwrap();\n");
        s.push_str("            let Some(entry) = tasks.get_mut(&joined) else {\n");
        s.push_str("                return;\n");
        s.push_str("            };\n");
        s.push_str("            if entry.joined {\n");
        s.push_str("                return;\n");
        s.push_str("            }\n");
        s.push_str("            if entry.finished {\n");
        s.push_str("                entry.joined = true;\n");
        s.push_str("                should_record = true;\n");
        s.push_str("            }\n");
        s.push_str("        }\n\n");

        s.push_str("        if !should_record {\n");
        s.push_str("            self.backend_request_join(joiner, joined);\n");
        s.push_str("            while !self.is_task_finished(joined) {\n");
        s.push_str("                self.backend_tick_or_step();\n");
        s.push_str("            }\n");
        s.push_str("            let mut tasks = self.tasks.lock().unwrap();\n");
        s.push_str("            if let Some(entry) = tasks.get_mut(&joined) {\n");
        s.push_str("                if !entry.joined {\n");
        s.push_str("                    entry.joined = true;\n");
        s.push_str("                    should_record = true;\n");
        s.push_str("                }\n");
        s.push_str("            }\n");
        s.push_str("        }\n\n");

        s.push_str("        if should_record {\n");
        s.push_str("            self.record_task_joined(joiner, joined);\n");
        s.push_str("        }\n");
        s.push_str("    }\n\n");
    } else {
        s.push_str("    fn join_task(&self, joiner: u64, joined: u64) {\n");
        s.push_str("        let handle = {\n");
        s.push_str("            let mut tasks = self.tasks.lock().unwrap();\n");
        s.push_str("            let Some(entry) = tasks.get_mut(&joined) else {\n");
        s.push_str("                return;\n");
        s.push_str("            };\n");
        s.push_str("            if entry.joined {\n");
        s.push_str("                return;\n");
        s.push_str("            }\n");
        s.push_str("            entry.joined = true;\n");
        s.push_str("            entry.handle.take()\n");
        s.push_str("        };\n\n");

        s.push_str("        if let Some(h) = handle {\n");
        s.push_str("            let _ = h.join();\n");
        s.push_str("        }\n\n");

        s.push_str("        self.record_task_joined(joiner, joined);\n");
        s.push_str("    }\n\n");
    }
    s.push_str("    fn cancel_subtree_bfs(&self, root: u64, reason: u32) {\n");
    s.push_str("        let _ = self.backend_cancel_bfs(root);\n");
    s.push_str("        let mut queue = VecDeque::new();\n");
    s.push_str("        queue.push_back(root);\n\n");

    s.push_str("        while let Some(task) = queue.pop_front() {\n");
    s.push_str("            let (kids, emit_cancel) = {\n");
    s.push_str("                let mut tasks = self.tasks.lock().unwrap();\n");
    s.push_str("                let Some(entry) = tasks.get_mut(&task) else {\n");
    s.push_str("                    continue;\n");
    s.push_str("                };\n");
    s.push_str("                entry.cancel.store(true, Ordering::SeqCst);\n");
    s.push_str("                let kids: Vec<u64> = entry.children.iter().copied().collect();\n");
    s.push_str("                let emit = if entry.finished {\n");
    s.push_str("                    false\n");
    s.push_str("                } else if entry.cancelled_emitted {\n");
    s.push_str("                    false\n");
    s.push_str("                } else {\n");
    s.push_str("                    entry.cancelled_emitted = true;\n");
    s.push_str("                    true\n");
    s.push_str("                };\n");
    s.push_str("                (kids, emit)\n");
    s.push_str("            };\n\n");

    s.push_str("            if emit_cancel {\n");
    s.push_str("                self.record_task_cancelled(task, reason);\n");
    s.push_str("            }\n\n");

    s.push_str("            for child in kids {\n");
    s.push_str("                queue.push_back(child);\n");
    s.push_str("            }\n");
    s.push_str("        }\n");
    s.push_str("    }\n\n");

    s.push_str("    fn join_remaining_as_root(&self) {\n");
    s.push_str("        let ids: Vec<u64> = {\n");
    s.push_str("            let tasks = self.tasks.lock().unwrap();\n");
    s.push_str("            tasks\n");
    s.push_str("                .iter()\n");
    s.push_str("                .filter_map(|(&id, entry)| {\n");
    s.push_str("                    if id == 0 || entry.joined {\n");
    s.push_str("                        None\n");
    s.push_str("                    } else {\n");
    s.push_str("                        Some(id)\n");
    s.push_str("                    }\n");
    s.push_str("                })\n");
    s.push_str("                .collect()\n");
    s.push_str("        };\n\n");

    s.push_str("        for id in ids {\n");
    s.push_str("            self.join_task(0, id);\n");
    s.push_str("        }\n");
    s.push_str("    }\n\n");

    s.push_str("    fn is_cancelled(&self, task: u64) -> bool {\n");
    s.push_str("        let tasks = self.tasks.lock().unwrap();\n");
    s.push_str("        tasks\n");
    s.push_str("            .get(&task)\n");
    s.push_str("            .map(|entry| entry.cancel.load(Ordering::SeqCst))\n");
    s.push_str("            .unwrap_or(false)\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    s.push_str("struct RootGuard {\n");
    s.push_str("    rt: Arc<Runtime>,\n");
    s.push_str("}\n\n");

    s.push_str("impl RootGuard {\n");
    s.push_str("    fn new(rt: Arc<Runtime>) -> Self {\n");
    s.push_str("        Self { rt }\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    s.push_str("impl Drop for RootGuard {\n");
    s.push_str("    fn drop(&mut self) {\n");
    s.push_str("        self.rt.cancel_subtree_bfs(0, CANCEL_REASON_BFS_SUBTREE);\n");
    s.push_str("        self.rt.join_remaining_as_root();\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    s.push_str("fn spawn_task<F>(rt: &Arc<Runtime>, parent: u64, f: F) -> u64\n");
    s.push_str("where\n");
    s.push_str("    F: FnOnce(Arc<Runtime>, u64) -> i32 + Send + 'static,\n");
    s.push_str("{\n");
    s.push_str("    Runtime::spawn_task(rt, parent, f)\n");
    s.push_str("}\n\n");

    s.push_str("fn join_task(rt: &Arc<Runtime>, joiner: u64, joined: u64) {\n");
    s.push_str("    rt.join_task(joiner, joined);\n");
    s.push_str("}\n\n");

    s.push_str("fn cancel_task(rt: &Arc<Runtime>, root: u64) {\n");
    s.push_str("    rt.cancel_subtree_bfs(root, CANCEL_REASON_BFS_SUBTREE);\n");
    s.push_str("}\n\n");

    s.push_str("fn cancelled(rt: &Arc<Runtime>, task: u64) -> bool {\n");
    s.push_str("    rt.is_cancelled(task)\n");
    s.push_str("}\n\n");

    s.push_str("fn fs_read(rt: &Arc<Runtime>, _task: u64, path_token: i64) -> i64 {\n");
    s.push_str("    let synthetic_path = format!(\"/virtual/{}\", path_token);\n");
    s.push_str("    match rt.fs_read(&synthetic_path) {\n");
    s.push_str("        Ok(bytes) => bytes.len() as i64,\n");
    s.push_str("        Err(_) => 0,\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    s.push_str("fn net_listen(_rt: &Arc<Runtime>, _task: u64, _port: i64) -> i64 {\n");
    s.push_str("    0\n");
    s.push_str("}\n\n");

    s.push_str("fn fuel_consume(_rt: &Arc<Runtime>, _task: u64, _units: i64) -> i64 {\n");
    s.push_str("    0\n");
    s.push_str("}\n\n");

    s.push_str(
        "fn bus_channel(_rt: &Arc<Runtime>, _task: u64, _channel: i64, _schema: i64) -> i64 {\n",
    );
    s.push_str("    0\n");
    s.push_str("}\n\n");

    s.push_str("fn bus_send(rt: &Arc<Runtime>, task: u64, channel: i64, schema: i64, payload: i64) -> i64 {\n");
    s.push_str("    let receiver = if channel < 0 { 0 } else { channel as u32 };\n");
    s.push_str("    let seq = if schema < 0 { 0 } else { schema as u64 };\n");
    s.push_str("    let kind = if payload < 0 { 0 } else { (payload as u64 & 0xffff) as u16 };\n");
    s.push_str("    let _ = (task, receiver, seq, kind);\n");
    s.push_str("    0\n");
    s.push_str("}\n\n");

    s.push_str("fn bus_recv(rt: &Arc<Runtime>, task: u64, channel: i64) -> i64 {\n");
    s.push_str("    let receiver = if channel < 0 { 0 } else { channel as u32 };\n");
    s.push_str("    let _ = (task, receiver);\n");
    s.push_str("    0\n");
    s.push_str("}\n\n");

    s.push_str("fn main() {\n");
    s.push_str("    let out_dir = std::env::var(\"NEX_OUT_DIR\")\n");
    s.push_str("        .ok()\n");
    s.push_str("        .filter(|v| !v.trim().is_empty())\n");
    s.push_str("        .map(std::path::PathBuf::from)\n");
    s.push_str("        .unwrap_or_else(|| std::path::PathBuf::from(\"./nex_out\"));\n");
    s.push_str("    let agent_id = std::env::var(\"NEX_AGENT_ID\")\n");
    s.push_str("        .ok()\n");
    s.push_str("        .and_then(|v| v.parse::<u32>().ok())\n");
    s.push_str(&format!("        .unwrap_or({});\n", agent_id));
    s.push_str("    std::fs::create_dir_all(&out_dir).unwrap();\n");
    s.push_str("    init_global_recorder_with_jsonl(&out_dir, \"events.bin\", \"events.jsonl\").unwrap();\n");
    s.push_str("    {\n");
    s.push_str("        let mut r = recorder().lock().unwrap();\n");
    s.push_str("        r.set_hashes(");
    s.push_str(&format!(
        "{:?}, {:?}, {:?}",
        codegen_hash, source_hash, policy_hash
    ));
    s.push_str(");\n");
    s.push_str("        r.set_agent_id(agent_id);\n");
    s.push_str("    }\n\n");
    s.push_str("    let runtime = Arc::new(Runtime::new());\n");
    s.push_str("    runtime.init_root();\n");
    s.push_str("    runtime.backend_tick_or_step();\n");
    s.push_str("    let guard = RootGuard::new(Arc::clone(&runtime));\n\n");

    s.push_str(
        "    let exit_code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> i32 {\n",
    );
    if has_nex_main(program) {
        s.push_str("        let _ = nex_main(&runtime, 0);\n");
    }
    s.push_str("        0\n");
    s.push_str("    }))\n");
    s.push_str("    .unwrap_or(1);\n\n");

    s.push_str("    drop(guard);\n");
    s.push_str("    let final_exit = runtime.backend_forced_exit_code().unwrap_or(exit_code);\n");
    s.push_str("    runtime.finish_root(final_exit);\n");
    s.push_str("    {\n");
    s.push_str("        let mut r = recorder().lock().unwrap();\n");
    s.push_str("        r.record_run_finished(0, final_exit).unwrap();\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    generate_functions(program, &mut s);

    s
}
fn has_nex_main(program: &Program) -> bool {
    program.items.iter().any(|item| match item {
        Item::Function(f) => f.name == "main",
        _ => false,
    })
}

fn generate_functions(program: &Program, out: &mut String) {
    for item in &program.items {
        if let Item::Function(f) = item {
            let name = mapped_func_name(&f.name);
            out.push_str(&format!("fn {}(_rt: &Arc<Runtime>, _task_id: u64", name));
            for p in &f.params {
                out.push_str(&format!(", {}: i64", sanitize_ident(&p.name)));
            }
            out.push_str(") -> i32 {\n");
            generate_block(&f.body, out, "_rt", "_task_id", 1);
            out.push_str("    0\n");
            out.push_str("}\n\n");
        }
    }
}

fn generate_block(block: &Block, out: &mut String, rt_var: &str, task_var: &str, indent: usize) {
    for stmt in &block.stmts {
        generate_stmt(stmt, out, rt_var, task_var, indent);
    }
}

fn generate_stmt(stmt: &Stmt, out: &mut String, rt_var: &str, task_var: &str, indent: usize) {
    let pad = "    ".repeat(indent);
    match stmt {
        Stmt::Let { name, value, .. } => {
            out.push_str(&format!(
                "{}let {} = {};\n",
                pad,
                sanitize_ident(name),
                generate_expr(value, rt_var, task_var, indent)
            ));
        }
        Stmt::Return(Some(e)) => {
            out.push_str(&format!(
                "{}return ({}) as i32;\n",
                pad,
                generate_expr(e, rt_var, task_var, indent)
            ));
        }
        Stmt::Return(None) => {
            out.push_str(&format!("{}return 0;\n", pad));
        }
        Stmt::Expr(e) => {
            out.push_str(&format!(
                "{}let _ = {};\n",
                pad,
                generate_expr(e, rt_var, task_var, indent)
            ));
        }
        Stmt::If {
            cond,
            then_block,
            else_block,
        } => {
            out.push_str(&format!(
                "{}if ({}) != 0 {{\n",
                pad,
                generate_expr(cond, rt_var, task_var, indent)
            ));
            generate_block(then_block, out, rt_var, task_var, indent + 1);
            if let Some(eb) = else_block {
                out.push_str(&format!("{}}} else {{\n", pad));
                generate_block(eb, out, rt_var, task_var, indent + 1);
            }
            out.push_str(&format!("{}}}\n", pad));
        }
        Stmt::Loop(body) => {
            out.push_str(&format!("{}loop {{\n", pad));
            generate_block(body, out, rt_var, task_var, indent + 1);
            out.push_str(&format!("{}}}\n", pad));
        }
        Stmt::Defer(body) => {
            generate_block(body, out, rt_var, task_var, indent);
        }
    }
}

fn generate_expr(expr: &Expr, rt_var: &str, task_var: &str, indent: usize) -> String {
    match expr {
        Expr::Literal(Literal::Int(i)) => format!("{}i64", i),
        Expr::Literal(Literal::Float(f)) => format!("{}f64 as i64", f),
        Expr::Literal(Literal::Bool(b)) => {
            if *b {
                "1i64".to_string()
            } else {
                "0i64".to_string()
            }
        }
        Expr::Literal(Literal::String(s)) => format!("(String::from({:?}).len() as i64)", s),
        Expr::Variable(v) => sanitize_ident(v),

        Expr::BinaryOp { left, op, right } => {
            let l = generate_expr(left, rt_var, task_var, indent);
            let r = generate_expr(right, rt_var, task_var, indent);
            match op {
                BinOp::Add => format!("(({}) + ({}))", l, r),
                BinOp::Sub => format!("(({}) - ({}))", l, r),
                BinOp::Mul => format!("(({}) * ({}))", l, r),
                BinOp::Div => format!("(({}) / ({}))", l, r),
                BinOp::Eq => format!("((( {}) == ( {} )) as i64)", l, r),
                BinOp::Ne => format!("((( {}) != ( {} )) as i64)", l, r),
                BinOp::Lt => format!("((( {}) < ( {} )) as i64)", l, r),
                BinOp::Le => format!("((( {}) <= ( {} )) as i64)", l, r),
                BinOp::Gt => format!("((( {}) > ( {} )) as i64)", l, r),
                BinOp::Ge => format!("((( {}) >= ( {} )) as i64)", l, r),
            }
        }

        Expr::Call { func, args, .. } => {
            if func == "cancel" && args.len() == 1 {
                let a0 = generate_expr(&args[0], rt_var, task_var, indent);
                return format!("{{ cancel_task({}, ({}) as u64); 0i64 }}", rt_var, a0);
            }

            if func == "join" && args.len() == 1 {
                let a0 = generate_expr(&args[0], rt_var, task_var, indent);
                return format!(
                    "{{ join_task({}, {}, ({}) as u64); 0i64 }}",
                    rt_var, task_var, a0
                );
            }

            if func == "cancelled" && args.is_empty() {
                return format!("(cancelled({}, {}) as i64)", rt_var, task_var);
            }

            let mapped = mapped_func_name(func);
            let mut rendered_args = Vec::new();
            for a in args {
                rendered_args.push(format!(
                    "({}) as i64",
                    generate_expr(a, rt_var, task_var, indent)
                ));
            }
            if rendered_args.is_empty() {
                format!("({}(&{}, {}) as i64)", mapped, rt_var, task_var)
            } else {
                format!(
                    "({}(&{}, {}, {}) as i64)",
                    mapped,
                    rt_var,
                    task_var,
                    rendered_args.join(", ")
                )
            }
        }

        Expr::Spawn { block, .. } => {
            let mut body = String::new();
            let pad = "    ".repeat(indent + 2);
            for st in &block.stmts {
                let mut local = String::new();
                generate_stmt(st, &mut local, "_rt_child", "_task_child", indent + 2);
                body.push_str(&local);
            }
            if body.is_empty() {
                body.push_str(&format!("{}let _ = 0;\n", pad));
            }

            format!(
                "{{ let __rt_spawn = Arc::clone({}); spawn_task(&__rt_spawn, {}, move |_rt_child: Arc<Runtime>, _task_child: u64| -> i32 {{ {}{}0 }}) }}",
                rt_var,
                task_var,
                body,
                "    ".repeat(indent + 2)
            )
        }

        Expr::If {
            cond,
            then_block,
            else_block,
        } => {
            let c = generate_expr(cond, rt_var, task_var, indent);
            let t = block_expr(then_block, rt_var, task_var, indent);
            let e = else_block
                .as_ref()
                .map(|b| block_expr(b, rt_var, task_var, indent))
                .unwrap_or_else(|| "0i64".to_string());
            format!("(if ({}) != 0 {{ {} }} else {{ {} }})", c, t, e)
        }

        Expr::Block(b) => block_expr(b, rt_var, task_var, indent),
    }
}

fn block_expr(block: &Block, rt_var: &str, task_var: &str, indent: usize) -> String {
    let mut s = String::new();
    s.push_str("{ ");
    for st in &block.stmts {
        match st {
            Stmt::Expr(e) => {
                s.push_str(&format!(
                    "let _ = {}; ",
                    generate_expr(e, rt_var, task_var, indent + 1)
                ));
            }
            Stmt::Let { name, value, .. } => {
                s.push_str(&format!(
                    "let {} = {}; ",
                    sanitize_ident(name),
                    generate_expr(value, rt_var, task_var, indent + 1)
                ));
            }
            _ => {
                s.push_str("let _ = 0; ");
            }
        }
    }
    s.push_str("0i64 }");
    s
}

fn mapped_func_name(name: &str) -> String {
    if name == "main" {
        "nex_main".to_string()
    } else {
        sanitize_ident(name)
    }
}

fn sanitize_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_".to_string()
    } else {
        out
    }
}
