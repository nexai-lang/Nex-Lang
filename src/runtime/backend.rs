// src/runtime/backend.rs
//
// Execution backend abstraction for runtime progression.
// Default remains threaded behavior; cooperative backend is feature-gated.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::event::{FuelReason, SchedState, YieldKind};
use super::event_recorder::try_recorder;
use super::scheduler::{AgentId, BlockReason, NoopSchedLog, SchedLog, Scheduler};
use super::task_context::TaskId;

const COOP_INITIAL_FUEL: u64 = 1024;
const COOP_DEBIT_TICK: u32 = 1;
const COOP_DEBIT_STEP: u32 = 4;
const COOP_EXIT_FUEL_EXHAUSTED: i32 = 70;
const COOP_EXIT_DEADLOCK: i32 = 75;

const DEADLOCK_KIND_JOIN_CYCLE: u8 = 1;
const DEADLOCK_KIND_RECV_ONLY: u8 = 2;
const DEADLOCK_KIND_MIXED: u8 = 3;
const DEADLOCK_KIND_UNRESOLVED: u8 = 4;

const DEADLOCK_REASON_JOIN_WAIT: u8 = 1;
const DEADLOCK_REASON_RECV_WAIT: u8 = 2;
const DEADLOCK_REASON_CYCLE_EDGE: u8 = 3;

pub trait ExecBackend {
    fn spawn(&mut self, parent: TaskId) -> TaskId;
    fn request_join(&mut self, waiter: TaskId, target: TaskId);
    fn block_on_recv(&mut self, task: TaskId, agent: AgentId);
    fn wake_recv_waiters(&mut self, agent: AgentId) -> Vec<TaskId>;
    fn cancel_bfs(&mut self, root: TaskId) -> Vec<TaskId>;
    fn tick_or_step(&mut self);

    fn run(&mut self);
    fn take_picked(&mut self) -> Option<TaskId>;
    fn complete(&mut self, task: TaskId, exit_code: i32);
    fn is_finished(&self) -> bool;
    fn forced_exit_code(&self) -> Option<i32>;
}

#[derive(Default)]
pub struct ThreadedBackend {
    next_task_id: TaskId,
    children: BTreeMap<TaskId, BTreeSet<TaskId>>,
    join_waiters: BTreeMap<TaskId, BTreeSet<TaskId>>,
    finished: BTreeSet<TaskId>,
}

impl ThreadedBackend {
    pub fn new() -> Self {
        let mut children = BTreeMap::new();
        children.insert(0, BTreeSet::new());
        Self {
            next_task_id: 1,
            children,
            join_waiters: BTreeMap::new(),
            finished: BTreeSet::new(),
        }
    }
}

impl ExecBackend for ThreadedBackend {
    fn spawn(&mut self, parent: TaskId) -> TaskId {
        let child = self.next_task_id;
        self.next_task_id = self.next_task_id.saturating_add(1);

        self.children.entry(parent).or_default().insert(child);
        self.children.entry(child).or_default();
        child
    }

    fn request_join(&mut self, waiter: TaskId, target: TaskId) {
        if self.finished.contains(&target) {
            return;
        }
        self.join_waiters.entry(target).or_default().insert(waiter);
    }

    fn block_on_recv(&mut self, _task: TaskId, _agent: AgentId) {}

    fn wake_recv_waiters(&mut self, _agent: AgentId) -> Vec<TaskId> {
        Vec::new()
    }

    fn cancel_bfs(&mut self, root: TaskId) -> Vec<TaskId> {
        if !self.children.contains_key(&root) {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut q = VecDeque::new();
        let mut seen = BTreeSet::new();

        q.push_back(root);
        seen.insert(root);

        while let Some(task) = q.pop_front() {
            out.push(task);
            if let Some(children) = self.children.get(&task) {
                for child in children {
                    if seen.insert(*child) {
                        q.push_back(*child);
                    }
                }
            }
        }

        out
    }

    fn tick_or_step(&mut self) {}

    fn run(&mut self) {}

    fn take_picked(&mut self) -> Option<TaskId> {
        None
    }

    fn complete(&mut self, task: TaskId, _exit_code: i32) {
        self.finished.insert(task);
    }

    fn is_finished(&self) -> bool {
        true
    }

    fn forced_exit_code(&self) -> Option<i32> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeadlockEdge {
    from: u32,
    to: u32,
    reason: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeadlockReport {
    tick: u64,
    blocked_count: u32,
    kind: u8,
    edges: Vec<DeadlockEdge>,
    cycle: Vec<u32>,
}

pub struct CoopBackend {
    scheduler: Scheduler,
    last_picked: Option<TaskId>,
    fuel_remaining: u64,
    exhausted: bool,
    forced_exit: Option<i32>,
    deadlock_report: Option<DeadlockReport>,
}

impl CoopBackend {
    pub fn new() -> Self {
        Self {
            scheduler: Scheduler::new(),
            last_picked: None,
            fuel_remaining: COOP_INITIAL_FUEL,
            exhausted: false,
            forced_exit: None,
            deadlock_report: None,
        }
    }

    fn to_sched_id(id: TaskId) -> u32 {
        u32::try_from(id).unwrap_or(u32::MAX)
    }

    fn with_sched_log<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Scheduler, &mut dyn SchedLog),
    {
        if let Some(rec) = try_recorder() {
            if let Ok(mut guard) = rec.lock() {
                f(&mut self.scheduler, &mut *guard);
                return;
            }
        }

        let mut noop = NoopSchedLog;
        f(&mut self.scheduler, &mut noop);
    }

    fn debit_fuel(&mut self, task: TaskId, amount: u32, reason: FuelReason) -> bool {
        let amount_u64 = u64::from(amount);
        if self.fuel_remaining < amount_u64 {
            self.trigger_fuel_exhausted(task);
            return false;
        }

        self.fuel_remaining -= amount_u64;

        if let Some(rec) = try_recorder() {
            if let Ok(mut guard) = rec.lock() {
                let _ = guard.record_fuel_debit(
                    0,
                    self.scheduler.tick,
                    Self::to_sched_id(task),
                    amount,
                    reason,
                );
            }
        }

        true
    }

    fn trigger_fuel_exhausted(&mut self, task: TaskId) {
        if self.exhausted {
            return;
        }

        self.exhausted = true;
        self.forced_exit = Some(COOP_EXIT_FUEL_EXHAUSTED);

        if let Some(rec) = try_recorder() {
            if let Ok(mut guard) = rec.lock() {
                let _ = guard.record_yield(
                    0,
                    self.scheduler.tick,
                    Self::to_sched_id(task),
                    YieldKind::FuelExhausted,
                );
            }
        }

        let _ = self.scheduler.cancel_bfs(0);
        self.with_sched_log(|scheduler, log| {
            scheduler.reevaluate_with_log(log);
            scheduler.force_finish_with_log(log);
        });
    }

    fn maybe_trigger_deadlock(&mut self) {
        if self.exhausted || self.scheduler.state == SchedState::Finished {
            return;
        }

        if !self.scheduler.runnable.is_empty() {
            return;
        }

        if !self.scheduler.has_unfinished_tasks() {
            return;
        }

        let blocked_snapshot = self.scheduler.blocked_snapshot();
        let blocked_count = blocked_snapshot.len() as u32;

        let mut join_edges = BTreeMap::new();
        let mut recv_only = !blocked_snapshot.is_empty();
        let mut edges: Vec<DeadlockEdge> = Vec::new();

        for (task, reason) in &blocked_snapshot {
            match reason {
                BlockReason::Join { target } => {
                    recv_only = false;
                    join_edges.insert(*task, *target);
                    edges.push(DeadlockEdge {
                        from: *task,
                        to: *target,
                        reason: DEADLOCK_REASON_JOIN_WAIT,
                    });
                }
                BlockReason::Recv { agent } => {
                    edges.push(DeadlockEdge {
                        from: *task,
                        to: *agent,
                        reason: DEADLOCK_REASON_RECV_WAIT,
                    });
                }
            }
        }

        let cycle = find_smallest_join_cycle(&join_edges).unwrap_or_default();
        if cycle.len() >= 2 {
            for idx in 0..cycle.len() {
                let next = if idx + 1 < cycle.len() {
                    cycle[idx + 1]
                } else {
                    cycle[0]
                };
                edges.push(DeadlockEdge {
                    from: cycle[idx],
                    to: next,
                    reason: DEADLOCK_REASON_CYCLE_EDGE,
                });
            }
        }

        let kind = if !cycle.is_empty() {
            DEADLOCK_KIND_JOIN_CYCLE
        } else if recv_only {
            DEADLOCK_KIND_RECV_ONLY
        } else if blocked_snapshot.is_empty() {
            DEADLOCK_KIND_UNRESOLVED
        } else {
            DEADLOCK_KIND_MIXED
        };

        let report = DeadlockReport {
            tick: self.scheduler.tick,
            blocked_count,
            kind,
            edges,
            cycle,
        };

        if let Some(rec) = try_recorder() {
            if let Ok(mut guard) = rec.lock() {
                let _ = guard.record_deadlock_detected(
                    0,
                    report.tick,
                    report.blocked_count,
                    report.kind,
                );
                for edge in &report.edges {
                    let _ = guard.record_deadlock_edge(0, edge.from, edge.to, edge.reason);
                }
            }
        }

        self.deadlock_report = Some(report);
        self.exhausted = true;
        self.forced_exit = Some(COOP_EXIT_DEADLOCK);

        self.with_sched_log(|scheduler, log| {
            scheduler.reevaluate_with_log(log);
            scheduler.force_finish_with_log(log);
        });
        self.last_picked = None;
    }

    #[cfg(test)]
    fn deadlock_report(&self) -> Option<&DeadlockReport> {
        self.deadlock_report.as_ref()
    }
}

impl ExecBackend for CoopBackend {
    fn spawn(&mut self, parent: TaskId) -> TaskId {
        if self.scheduler.state == SchedState::Init && !self.scheduler.has_task(0) {
            self.with_sched_log(|scheduler, log| {
                scheduler.init_root_with_log(0, log);
            });
        }

        let child = self.scheduler.spawn_child(Self::to_sched_id(parent));
        u64::from(child)
    }

    fn request_join(&mut self, waiter: TaskId, target: TaskId) {
        self.scheduler
            .request_join(Self::to_sched_id(waiter), Self::to_sched_id(target));
    }

    fn block_on_recv(&mut self, task: TaskId, agent: AgentId) {
        if self.scheduler.state == SchedState::Finished || self.exhausted {
            return;
        }

        let task_u32 = Self::to_sched_id(task);
        if !self.scheduler.block_on_recv(task_u32, agent) {
            return;
        }

        if let Some(rec) = try_recorder() {
            if let Ok(mut guard) = rec.lock() {
                let _ =
                    guard.record_yield(0, self.scheduler.tick, task_u32, YieldKind::RecvBlocked);
            }
        }

        self.with_sched_log(|scheduler, log| {
            scheduler.reevaluate_with_log(log);
        });
        self.last_picked = None;
    }

    fn wake_recv_waiters(&mut self, agent: AgentId) -> Vec<TaskId> {
        let mut woken = Vec::new();
        self.with_sched_log(|scheduler, log| {
            woken = scheduler
                .wake_recv_waiters(agent)
                .into_iter()
                .map(u64::from)
                .collect();
            scheduler.reevaluate_with_log(log);
        });
        woken
    }

    fn cancel_bfs(&mut self, root: TaskId) -> Vec<TaskId> {
        self.scheduler
            .cancel_bfs(Self::to_sched_id(root))
            .into_iter()
            .map(u64::from)
            .collect()
    }

    fn tick_or_step(&mut self) {
        self.run();
    }

    fn run(&mut self) {
        if self.scheduler.state == SchedState::Finished || self.exhausted {
            self.last_picked = None;
            return;
        }

        if self.scheduler.state == SchedState::Init {
            self.with_sched_log(|scheduler, log| {
                scheduler.init_root_with_log(0, log);
            });
        }

        if !self.debit_fuel(0, COOP_DEBIT_TICK, FuelReason::Tick) {
            self.last_picked = None;
            return;
        }

        let mut picked = None;
        self.with_sched_log(|scheduler, log| {
            picked = scheduler.tick_once_with_log(log).map(u64::from);
            scheduler.reevaluate_with_log(log);
        });
        self.last_picked = picked;

        if self.last_picked.is_none() {
            self.with_sched_log(|scheduler, log| {
                if scheduler.state == SchedState::Draining
                    && scheduler.runnable.is_empty()
                    && scheduler.blocked.is_empty()
                    && scheduler.all_tasks_terminal()
                {
                    scheduler.force_finish_with_log(log);
                }
            });
            self.maybe_trigger_deadlock();
        }
    }

    fn take_picked(&mut self) -> Option<TaskId> {
        self.last_picked.take()
    }

    fn complete(&mut self, task: TaskId, exit_code: i32) {
        if self.exhausted {
            return;
        }

        self.scheduler
            .mark_finished(Self::to_sched_id(task), exit_code);

        if !self.debit_fuel(task, COOP_DEBIT_STEP, FuelReason::Step) {
            return;
        }

        self.with_sched_log(|scheduler, log| {
            scheduler.reevaluate_with_log(log);
            if scheduler.state == SchedState::Draining
                && scheduler.runnable.is_empty()
                && scheduler.blocked.is_empty()
                && scheduler.all_tasks_terminal()
            {
                scheduler.force_finish_with_log(log);
            }
        });
    }

    fn is_finished(&self) -> bool {
        self.scheduler.state == SchedState::Finished || self.exhausted
    }

    fn forced_exit_code(&self) -> Option<i32> {
        self.forced_exit
    }
}

fn find_smallest_join_cycle(join_edges: &BTreeMap<u32, u32>) -> Option<Vec<u32>> {
    let mut best: Option<Vec<u32>> = None;

    for root in join_edges.keys() {
        let mut path: Vec<u32> = Vec::new();
        let mut seen_at: BTreeMap<u32, usize> = BTreeMap::new();
        let mut current = *root;

        loop {
            if let Some(idx) = seen_at.get(&current).copied() {
                let cycle = normalize_cycle(&path[idx..]);
                if !cycle.is_empty() {
                    match &best {
                        Some(prev) if *prev <= cycle => {}
                        _ => best = Some(cycle),
                    }
                }
                break;
            }

            let Some(next) = join_edges.get(&current).copied() else {
                break;
            };

            seen_at.insert(current, path.len());
            path.push(current);
            current = next;
        }
    }

    best
}

fn normalize_cycle(cycle: &[u32]) -> Vec<u32> {
    if cycle.is_empty() {
        return Vec::new();
    }

    let mut best: Option<Vec<u32>> = None;
    for offset in 0..cycle.len() {
        let mut rotated = Vec::with_capacity(cycle.len());
        rotated.extend_from_slice(&cycle[offset..]);
        rotated.extend_from_slice(&cycle[..offset]);
        match &best {
            Some(prev) if *prev <= rotated => {}
            _ => best = Some(rotated),
        }
    }

    best.unwrap_or_default()
}

pub enum BackendKind {
    Threaded(ThreadedBackend),
    Coop(CoopBackend),
}

impl BackendKind {
    pub fn new() -> Self {
        #[cfg(feature = "coop_scheduler")]
        {
            Self::Coop(CoopBackend::new())
        }
        #[cfg(not(feature = "coop_scheduler"))]
        {
            Self::Threaded(ThreadedBackend::new())
        }
    }
}

impl ExecBackend for BackendKind {
    fn spawn(&mut self, parent: TaskId) -> TaskId {
        match self {
            BackendKind::Threaded(b) => b.spawn(parent),
            BackendKind::Coop(b) => b.spawn(parent),
        }
    }

    fn request_join(&mut self, waiter: TaskId, target: TaskId) {
        match self {
            BackendKind::Threaded(b) => b.request_join(waiter, target),
            BackendKind::Coop(b) => b.request_join(waiter, target),
        }
    }

    fn block_on_recv(&mut self, task: TaskId, agent: AgentId) {
        match self {
            BackendKind::Threaded(b) => b.block_on_recv(task, agent),
            BackendKind::Coop(b) => b.block_on_recv(task, agent),
        }
    }

    fn wake_recv_waiters(&mut self, agent: AgentId) -> Vec<TaskId> {
        match self {
            BackendKind::Threaded(b) => b.wake_recv_waiters(agent),
            BackendKind::Coop(b) => b.wake_recv_waiters(agent),
        }
    }

    fn cancel_bfs(&mut self, root: TaskId) -> Vec<TaskId> {
        match self {
            BackendKind::Threaded(b) => b.cancel_bfs(root),
            BackendKind::Coop(b) => b.cancel_bfs(root),
        }
    }

    fn tick_or_step(&mut self) {
        match self {
            BackendKind::Threaded(b) => b.tick_or_step(),
            BackendKind::Coop(b) => b.tick_or_step(),
        }
    }

    fn run(&mut self) {
        match self {
            BackendKind::Threaded(b) => b.run(),
            BackendKind::Coop(b) => b.run(),
        }
    }

    fn take_picked(&mut self) -> Option<TaskId> {
        match self {
            BackendKind::Threaded(b) => b.take_picked(),
            BackendKind::Coop(b) => b.take_picked(),
        }
    }

    fn complete(&mut self, task: TaskId, exit_code: i32) {
        match self {
            BackendKind::Threaded(b) => b.complete(task, exit_code),
            BackendKind::Coop(b) => b.complete(task, exit_code),
        }
    }

    fn is_finished(&self) -> bool {
        match self {
            BackendKind::Threaded(b) => b.is_finished(),
            BackendKind::Coop(b) => b.is_finished(),
        }
    }

    fn forced_exit_code(&self) -> Option<i32> {
        match self {
            BackendKind::Threaded(b) => b.forced_exit_code(),
            BackendKind::Coop(b) => b.forced_exit_code(),
        }
    }
}

#[cfg(all(test, feature = "coop_scheduler"))]
mod tests {
    use super::{
        CoopBackend, ExecBackend, COOP_EXIT_DEADLOCK, COOP_EXIT_FUEL_EXHAUSTED,
        DEADLOCK_KIND_JOIN_CYCLE, DEADLOCK_KIND_MIXED, DEADLOCK_KIND_RECV_ONLY,
        DEADLOCK_REASON_JOIN_WAIT, DEADLOCK_REASON_RECV_WAIT,
    };
    use crate::runtime::agent_bus::{Mailbox, Message};
    use crate::runtime::event_reader::{EventReader, KIND_BUS_RECV, LOG_HEADER_LEN};
    use crate::runtime::event_recorder::EventRecorder;
    use std::fs;
    use std::io::BufReader;

    #[test]
    fn coop_spawn_order_is_stable() {
        let mut b = CoopBackend::new();
        let c1 = b.spawn(0);
        let c2 = b.spawn(0);

        b.run();
        let first = b.take_picked();
        b.run();
        let second = b.take_picked();
        b.run();
        let third = b.take_picked();

        assert_eq!(first, Some(0));
        assert_eq!(second, Some(c1));
        assert_eq!(third, Some(c2));
    }

    #[test]
    fn coop_join_wake_order_is_stable() {
        let mut b = CoopBackend::new();
        let target = b.spawn(0);
        let w1 = b.spawn(0);
        let w2 = b.spawn(0);

        b.request_join(w2, target);
        b.request_join(w1, target);
        b.complete(target, 0);

        b.run();
        let _ = b.take_picked();
        b.run();
        let next = b.take_picked();
        b.run();
        let next2 = b.take_picked();

        assert_eq!(next, Some(w1));
        assert_eq!(next2, Some(w2));
    }

    #[test]
    fn coop_cancel_bfs_is_stable() {
        let mut b = CoopBackend::new();
        let t1 = b.spawn(0);
        let t2 = b.spawn(0);
        let t3 = b.spawn(t1);
        let t4 = b.spawn(t1);
        let t5 = b.spawn(t2);

        let order = b.cancel_bfs(0);
        assert_eq!(order, vec![0, t1, t2, t3, t4, t5]);
    }

    #[test]
    fn coop_fuel_exhaustion_is_deterministic() {
        let mut b = CoopBackend::new();

        for _ in 0..400 {
            let _ = b.spawn(0);
        }

        for _ in 0..600 {
            if b.is_finished() {
                break;
            }

            b.run();
            if let Some(task) = b.take_picked() {
                b.complete(task, 0);
            }
        }

        assert_eq!(b.forced_exit_code(), Some(COOP_EXIT_FUEL_EXHAUSTED));
        assert!(b.is_finished());
    }

    #[test]
    fn coop_recv_blocks_until_send() {
        let mut b = CoopBackend::new();
        let receiver_task = b.spawn(0);
        let sender_task = b.spawn(0);
        let receiver_agent = 42u32;

        let mut mailbox = Mailbox::new();
        assert!(mailbox.recv(receiver_agent).message.is_none());

        b.block_on_recv(receiver_task, receiver_agent);

        for _ in 0..2 {
            b.run();
            if let Some(task) = b.take_picked() {
                assert_ne!(task, receiver_task);
                b.complete(task, 0);
            }
        }

        let base = std::env::temp_dir().join("nex_coop_recv_blocks_until_send");
        let out_dir = base.join("out");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&out_dir).expect("create out dir");

        let mut rec = EventRecorder::open(&out_dir, "events.bin").expect("open recorder");
        rec.record_task_started(0).expect("record task started");

        let send_out = mailbox.send(
            7,
            receiver_agent,
            Message {
                req_id: 0,
                channel_id: 0,
                sender: 0,
                sender_seq: 1,
                seq: 1,
                kind: 99,
                schema_id: 1,
                payload: Vec::new(),
            },
        );
        rec.record_bus_send(0, send_out.req_id, 7, receiver_agent, 99, 0, 0)
            .expect("record bus send");

        let woken = b.wake_recv_waiters(receiver_agent);
        assert_eq!(woken, vec![receiver_task]);

        b.run();
        let picked = b.take_picked();
        assert_eq!(picked, Some(receiver_task));
        b.complete(receiver_task, 0);
        b.complete(sender_task, 0);

        let received = mailbox
            .recv(receiver_agent)
            .message
            .expect("receiver should consume queued message");
        assert_eq!(received.req_id, send_out.req_id);
        rec.record_bus_recv(0, received.req_id, receiver_agent)
            .expect("record bus recv");
        rec.record_task_finished(0, 0)
            .expect("record task finished");
        rec.record_run_finished(0, 0).expect("record run finished");
        drop(rec);

        let events_path = out_dir.join("events.bin");
        let file = fs::File::open(&events_path).expect("open events");
        let mut reader = EventReader::new(BufReader::new(file));
        reader.read_log_header().expect("header");

        let mut saw_bus_recv = false;
        while let Some(ev) = reader.read_next().expect("read event") {
            if ev.kind == KIND_BUS_RECV {
                saw_bus_recv = true;
                break;
            }
        }

        assert_eq!(LOG_HEADER_LEN, 76);
        assert!(saw_bus_recv, "BusRecv event should be present");
    }

    #[test]
    fn coop_recv_wake_order_is_stable() {
        let mut b = CoopBackend::new();
        let waiter_a = b.spawn(0);
        let waiter_b = b.spawn(0);
        let agent = 9u32;

        b.block_on_recv(waiter_b, agent);
        b.block_on_recv(waiter_a, agent);

        let woken = b.wake_recv_waiters(agent);
        assert_eq!(woken, vec![waiter_a, waiter_b]);
    }

    #[test]
    fn join_cycle_deadlock_detected() {
        let mut b = CoopBackend::new();
        let t1 = b.spawn(0);
        let t2 = b.spawn(0);

        b.request_join(0, t1);
        b.request_join(t1, t2);
        b.request_join(t2, t1);

        b.run();

        assert!(b.take_picked().is_none());
        assert_eq!(b.forced_exit_code(), Some(COOP_EXIT_DEADLOCK));
        assert!(b.is_finished());

        let report = b.deadlock_report().expect("deadlock report");
        assert_eq!(report.kind, DEADLOCK_KIND_JOIN_CYCLE);
        assert_eq!(report.blocked_count, 3);
        assert_eq!(report.cycle, vec![1, 2]);
    }

    #[test]
    fn recv_only_deadlock_detected() {
        let mut b = CoopBackend::new();
        let t1 = b.spawn(0);

        b.block_on_recv(0, 10);
        b.block_on_recv(t1, 11);

        b.run();

        assert!(b.take_picked().is_none());
        assert_eq!(b.forced_exit_code(), Some(COOP_EXIT_DEADLOCK));

        let report = b.deadlock_report().expect("deadlock report");
        assert_eq!(report.kind, DEADLOCK_KIND_RECV_ONLY);
        assert_eq!(report.blocked_count, 2);
    }

    #[test]
    fn report_is_deterministic() {
        let mut b = CoopBackend::new();
        let t1 = b.spawn(0);
        let t2 = b.spawn(0);
        let t3 = b.spawn(0);

        b.block_on_recv(t3, 7);
        b.request_join(t2, t1);
        b.block_on_recv(t1, 8);
        b.request_join(0, t3);

        b.run();

        let report = b.deadlock_report().expect("deadlock report");
        assert_eq!(report.kind, DEADLOCK_KIND_MIXED);
        assert_eq!(report.blocked_count, 4);

        let blocked_edges: Vec<(u32, u32, u8)> = report
            .edges
            .iter()
            .filter(|edge| {
                edge.reason == DEADLOCK_REASON_JOIN_WAIT || edge.reason == DEADLOCK_REASON_RECV_WAIT
            })
            .map(|edge| (edge.from, edge.to, edge.reason))
            .collect();

        assert_eq!(
            blocked_edges,
            vec![
                (0, t3 as u32, DEADLOCK_REASON_JOIN_WAIT),
                (t1 as u32, 8, DEADLOCK_REASON_RECV_WAIT),
                (t2 as u32, t1 as u32, DEADLOCK_REASON_JOIN_WAIT),
                (t3 as u32, 7, DEADLOCK_REASON_RECV_WAIT),
            ]
        );
    }
}
