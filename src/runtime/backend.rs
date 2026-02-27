// src/runtime/backend.rs
//
// Execution backend abstraction for runtime progression.
// Default remains threaded behavior; cooperative backend is feature-gated.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::event::{FuelReason, SchedState, YieldKind};
use super::event_recorder::try_recorder;
use super::scheduler::{NoopSchedLog, SchedLog, Scheduler};
use super::task_context::TaskId;

const COOP_INITIAL_FUEL: u64 = 1024;
const COOP_DEBIT_TICK: u32 = 1;
const COOP_DEBIT_STEP: u32 = 4;
const COOP_EXIT_FUEL_EXHAUSTED: i32 = 70;

pub trait ExecBackend {
    fn spawn(&mut self, parent: TaskId) -> TaskId;
    fn request_join(&mut self, waiter: TaskId, target: TaskId);
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

pub struct CoopBackend {
    scheduler: Scheduler,
    last_picked: Option<TaskId>,
    fuel_remaining: u64,
    exhausted: bool,
    forced_exit: Option<i32>,
}

impl CoopBackend {
    pub fn new() -> Self {
        Self {
            scheduler: Scheduler::new(),
            last_picked: None,
            fuel_remaining: COOP_INITIAL_FUEL,
            exhausted: false,
            forced_exit: None,
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
    use super::{CoopBackend, ExecBackend, COOP_EXIT_FUEL_EXHAUSTED};

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
}
