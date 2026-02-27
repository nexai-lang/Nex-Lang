// src/runtime/scheduler.rs
//
// Deterministic single-thread cooperative scheduler core.
// This module is pure state management and does not execute tasks.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::event::{FuelReason, SchedState, YieldKind};
use super::event_recorder::EventRecorder;

pub type TaskId = u32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskStatus {
    Runnable,
    BlockedJoin { target: TaskId },
    Canceled,
    Finished { exit_code: i32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskState {
    pub parent: Option<TaskId>,
    pub children: BTreeSet<TaskId>,
    pub status: TaskStatus,
}

pub trait SchedLog {
    fn sched_init(&mut self, tick0: u64);
    fn sched_state(&mut self, from: SchedState, to: SchedState, tick: u64);
    fn tick_start(&mut self, tick: u64);
    fn pick_task(&mut self, tick: u64, task_id: TaskId, reason: &'static str);
    fn tick_end(&mut self, tick: u64, runnable: u32, blocked: u32);
}

pub struct NoopSchedLog;

impl SchedLog for NoopSchedLog {
    fn sched_init(&mut self, _tick0: u64) {}
    fn sched_state(&mut self, _from: SchedState, _to: SchedState, _tick: u64) {}
    fn tick_start(&mut self, _tick: u64) {}
    fn pick_task(&mut self, _tick: u64, _task_id: TaskId, _reason: &'static str) {}
    fn tick_end(&mut self, _tick: u64, _runnable: u32, _blocked: u32) {}
}

impl SchedLog for EventRecorder {
    fn sched_init(&mut self, tick0: u64) {
        let _ = self.record_sched_init(0, tick0);
    }

    fn sched_state(&mut self, from: SchedState, to: SchedState, tick: u64) {
        let _ = self.record_sched_state(0, from, to, tick);
    }

    fn tick_start(&mut self, tick: u64) {
        let _ = self.record_tick_start(0, tick);
    }

    fn pick_task(&mut self, tick: u64, task_id: TaskId, reason: &'static str) {
        let _ = self.record_pick_task(0, tick, task_id, reason);
    }

    fn tick_end(&mut self, tick: u64, runnable: u32, blocked: u32) {
        let _ = self.record_tick_end(0, tick, runnable, blocked);
    }
}

pub struct Scheduler {
    pub tick: u64,
    pub state: SchedState,
    pub runnable: BTreeSet<TaskId>,
    pub tasks: BTreeMap<TaskId, TaskState>,
    pub join_waiters: BTreeMap<TaskId, BTreeSet<TaskId>>,
    pub blocked: BTreeSet<TaskId>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            tick: 0,
            state: SchedState::Init,
            runnable: BTreeSet::new(),
            tasks: BTreeMap::new(),
            join_waiters: BTreeMap::new(),
            blocked: BTreeSet::new(),
        }
    }

    pub fn init_root(&mut self, root_id: TaskId) {
        let mut log = NoopSchedLog;
        self.init_root_with_log(root_id, &mut log);
    }

    pub fn init_root_with_log(&mut self, root_id: TaskId, log: &mut dyn SchedLog) {
        self.tasks.entry(root_id).or_insert_with(|| TaskState {
            parent: None,
            children: BTreeSet::new(),
            status: TaskStatus::Runnable,
        });

        self.runnable.insert(root_id);
        self.blocked.remove(&root_id);

        if self.state == SchedState::Init {
            log.sched_init(self.tick);
            self.transition_state(SchedState::Running, log);
        }
    }

    pub fn spawn_child(&mut self, parent: TaskId) -> TaskId {
        let child_id = self.next_id();

        self.tasks.entry(parent).or_insert_with(|| TaskState {
            parent: None,
            children: BTreeSet::new(),
            status: TaskStatus::Runnable,
        });

        if let Some(parent_state) = self.tasks.get_mut(&parent) {
            parent_state.children.insert(child_id);
        }

        self.tasks.insert(
            child_id,
            TaskState {
                parent: Some(parent),
                children: BTreeSet::new(),
                status: TaskStatus::Runnable,
            },
        );
        self.runnable.insert(child_id);
        self.blocked.remove(&child_id);

        child_id
    }

    pub fn request_join(&mut self, waiter: TaskId, target: TaskId) {
        if waiter == target {
            return;
        }

        let Some(waiter_state) = self.tasks.get(&waiter) else {
            return;
        };
        if !matches!(waiter_state.status, TaskStatus::Runnable) {
            return;
        }

        let Some(target_state) = self.tasks.get(&target) else {
            return;
        };
        if matches!(
            target_state.status,
            TaskStatus::Finished { .. } | TaskStatus::Canceled
        ) {
            return;
        }

        if let Some(waiter_state) = self.tasks.get_mut(&waiter) {
            waiter_state.status = TaskStatus::BlockedJoin { target };
        }

        self.runnable.remove(&waiter);
        self.blocked.insert(waiter);
        self.join_waiters.entry(target).or_default().insert(waiter);
    }

    pub fn mark_finished(&mut self, task: TaskId, exit_code: i32) {
        if let Some(state) = self.tasks.get_mut(&task) {
            state.status = TaskStatus::Finished { exit_code };
        } else {
            self.tasks.insert(
                task,
                TaskState {
                    parent: None,
                    children: BTreeSet::new(),
                    status: TaskStatus::Finished { exit_code },
                },
            );
        }

        self.runnable.remove(&task);
        self.blocked.remove(&task);

        self.remove_waiter_from_all(task);

        if let Some(waiters) = self.join_waiters.remove(&task) {
            for waiter in waiters {
                if let Some(waiter_state) = self.tasks.get_mut(&waiter) {
                    waiter_state.status = TaskStatus::Runnable;
                } else {
                    self.tasks.insert(
                        waiter,
                        TaskState {
                            parent: None,
                            children: BTreeSet::new(),
                            status: TaskStatus::Runnable,
                        },
                    );
                }
                self.blocked.remove(&waiter);
                self.runnable.insert(waiter);
            }
        }
    }

    pub fn cancel_bfs(&mut self, root: TaskId) -> Vec<TaskId> {
        if !self.tasks.contains_key(&root) {
            return Vec::new();
        }

        let mut queue: VecDeque<TaskId> = VecDeque::new();
        let mut visited: BTreeSet<TaskId> = BTreeSet::new();
        let mut out: Vec<TaskId> = Vec::new();

        queue.push_back(root);
        visited.insert(root);

        while let Some(task_id) = queue.pop_front() {
            out.push(task_id);

            let children: Vec<TaskId> = if let Some(task_state) = self.tasks.get_mut(&task_id) {
                match task_state.status {
                    TaskStatus::Finished { .. } | TaskStatus::Canceled => {}
                    _ => {
                        task_state.status = TaskStatus::Canceled;
                    }
                }
                task_state.children.iter().copied().collect()
            } else {
                Vec::new()
            };

            self.runnable.remove(&task_id);
            self.blocked.remove(&task_id);
            self.remove_waiter_from_all(task_id);

            for child in children {
                if visited.insert(child) {
                    queue.push_back(child);
                }
            }
        }

        out
    }

    pub fn tick_once(&mut self) -> Option<TaskId> {
        let mut log = NoopSchedLog;
        self.tick_once_with_log(&mut log)
    }

    pub fn tick_once_with_log(&mut self, log: &mut dyn SchedLog) -> Option<TaskId> {
        if self.state == SchedState::Init || self.state == SchedState::Finished {
            return None;
        }

        let tick_now = self.tick;
        log.tick_start(tick_now);

        let picked = self.runnable.pop_first();
        if let Some(task_id) = picked {
            log.pick_task(tick_now, task_id, "runnable_asc");
        }

        log.tick_end(
            tick_now,
            self.runnable.len() as u32,
            self.blocked.len() as u32,
        );

        self.tick = self.tick.saturating_add(1);
        self.reevaluate_with_log(log);

        picked
    }

    pub fn has_task(&self, task: TaskId) -> bool {
        self.tasks.contains_key(&task)
    }

    pub fn is_task_finished(&self, task: TaskId) -> bool {
        self.tasks
            .get(&task)
            .map(|state| {
                matches!(
                    state.status,
                    TaskStatus::Finished { .. } | TaskStatus::Canceled
                )
            })
            .unwrap_or(false)
    }

    pub fn all_tasks_terminal(&self) -> bool {
        self.tasks.values().all(|state| {
            matches!(
                state.status,
                TaskStatus::Finished { .. } | TaskStatus::Canceled
            )
        })
    }

    pub fn reevaluate_with_log(&mut self, log: &mut dyn SchedLog) {
        if self.state == SchedState::Running && self.runnable.is_empty() {
            self.transition_state(SchedState::Draining, log);
        }

        if self.state == SchedState::Draining
            && self.runnable.is_empty()
            && self.blocked.is_empty()
            && self.all_tasks_terminal()
        {
            self.transition_state(SchedState::Finished, log);
        }
    }

    pub fn force_finish_with_log(&mut self, log: &mut dyn SchedLog) {
        if self.state != SchedState::Finished {
            self.transition_state(SchedState::Finished, log);
        }
    }

    fn next_id(&self) -> TaskId {
        match self.tasks.last_key_value() {
            Some((max_id, _)) => max_id.saturating_add(1),
            None => 0,
        }
    }

    fn remove_waiter_from_all(&mut self, waiter: TaskId) {
        let targets: Vec<TaskId> = self.join_waiters.keys().copied().collect();
        for target in targets {
            if let Some(waiters) = self.join_waiters.get_mut(&target) {
                waiters.remove(&waiter);
                if waiters.is_empty() {
                    self.join_waiters.remove(&target);
                }
            }
        }
    }

    fn transition_state(&mut self, to: SchedState, log: &mut dyn SchedLog) {
        if self.state != to {
            let from = self.state;
            self.state = to;
            log.sched_state(from, to, self.tick);
        }
    }

    #[allow(clippy::unused_self)]
    fn _touch_event_enums(&self, _yield_kind: YieldKind, _fuel_reason: FuelReason) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CapturingLog {
        tick_starts: Vec<u64>,
        tick_ends: Vec<u64>,
    }

    impl SchedLog for CapturingLog {
        fn sched_init(&mut self, _tick0: u64) {}
        fn sched_state(&mut self, _from: SchedState, _to: SchedState, _tick: u64) {}
        fn tick_start(&mut self, tick: u64) {
            self.tick_starts.push(tick);
        }
        fn pick_task(&mut self, _tick: u64, _task_id: TaskId, _reason: &'static str) {}
        fn tick_end(&mut self, tick: u64, _runnable: u32, _blocked: u32) {
            self.tick_ends.push(tick);
        }
    }

    #[test]
    fn test_pick_order_is_ascending() {
        let mut s = Scheduler::new();
        s.init_root(0);
        s.spawn_child(0);
        s.spawn_child(0);
        s.spawn_child(0);

        assert_eq!(s.tick_once(), Some(0));
        assert_eq!(s.tick_once(), Some(1));
        assert_eq!(s.tick_once(), Some(2));
        assert_eq!(s.tick_once(), Some(3));
    }

    #[test]
    fn test_spawn_assigns_monotonic_ids() {
        let mut s = Scheduler::new();
        s.init_root(0);

        let a = s.spawn_child(0);
        let b = s.spawn_child(0);
        let c = s.spawn_child(0);

        assert_eq!(a, 1);
        assert_eq!(b, 2);
        assert_eq!(c, 3);
    }

    #[test]
    fn test_join_wake_order_is_ascending() {
        let mut s = Scheduler::new();
        s.init_root(0);

        let target = s.spawn_child(0);
        let waiter_a = s.spawn_child(0);
        let waiter_b = s.spawn_child(0);

        s.request_join(waiter_b, target);
        s.request_join(waiter_a, target);

        s.mark_finished(target, 0);
        s.mark_finished(0, 0);

        assert_eq!(s.tick_once(), Some(waiter_a));
        assert_eq!(s.tick_once(), Some(waiter_b));
    }

    #[test]
    fn test_cancel_bfs_is_deterministic() {
        let mut s = Scheduler::new();
        s.init_root(0);

        let t1 = s.spawn_child(0);
        let t2 = s.spawn_child(0);
        let t3 = s.spawn_child(t1);
        let t4 = s.spawn_child(t1);
        let t5 = s.spawn_child(t2);

        let order = s.cancel_bfs(0);
        assert_eq!(order, vec![0, t1, t2, t3, t4, t5]);
    }

    #[test]
    fn test_tick_monotonicity() {
        let mut s = Scheduler::new();
        s.init_root(0);
        s.spawn_child(0);

        let mut log = CapturingLog::default();
        let _ = s.tick_once_with_log(&mut log);
        let _ = s.tick_once_with_log(&mut log);

        assert_eq!(log.tick_starts, vec![0, 1]);
        assert_eq!(log.tick_ends, vec![0, 1]);
        assert_eq!(s.tick, 2);
    }
}
