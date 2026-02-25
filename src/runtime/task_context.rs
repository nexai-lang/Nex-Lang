// src/runtime/task_context.rs

use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use super::event_recorder;

pub type TaskId = u64;
pub const FUEL_API_VERSION: u32 = 1;
pub type Fuel = u64;

// Stable reason codes for cancellation (deterministic)
pub const CANCEL_REASON_BFS_SUBTREE: u32 = 1;
pub const CANCEL_REASON_FUEL_EXHAUSTED: u32 = 2;

#[derive(Clone)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn from_arc(flag: Arc<AtomicBool>) -> Self {
        Self { flag }
    }

    pub fn as_arc(&self) -> Arc<AtomicBool> {
        self.flag.clone()
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
pub enum AuditEvent {
    TaskSpawned {
        parent: TaskId,
        child: TaskId,
    },
    CapabilityInvoked {
        task: TaskId,
        capability: String,
        target: String,
    },
    ResourceViolation {
        task: TaskId,
        kind: ResourceViolationKind,
        detail: String,
    },
}

#[derive(Debug, Clone)]
pub enum ResourceViolationKind {
    FuelExhausted,
    MemoryExceeded,
    CapabilityDenied, // 🔐 NEW
}

pub trait AuditSink: Send + Sync + 'static {
    fn emit(&self, event: AuditEvent);
}

pub trait TaskRegistry: Send + Sync + 'static {
    fn children_of(&self, task: TaskId) -> Vec<TaskId>;
    fn mark_cancelled(&self, task: TaskId);
    fn cancel_token_of(&self, task: TaskId) -> CancelToken;
}

pub struct TaskContext {
    fuel_api_version: u32,
    task_id: TaskId,
    parent_id: Option<TaskId>,
    fuel_remaining: AtomicU64,
    token: CancelToken,
    registry: Arc<dyn TaskRegistry>,
    audit: Arc<dyn AuditSink>,
}

impl TaskContext {
    pub fn new(
        task_id: TaskId,
        parent_id: Option<TaskId>,
        initial_fuel: Fuel,
        token: CancelToken,
        registry: Arc<dyn TaskRegistry>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            fuel_api_version: FUEL_API_VERSION,
            task_id,
            parent_id,
            fuel_remaining: AtomicU64::new(initial_fuel),
            token,
            registry,
            audit,
        }
    }

    // --- Accessors ---
    pub fn fuel_api_version(&self) -> u32 {
        self.fuel_api_version
    }

    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    pub fn parent_id(&self) -> Option<TaskId> {
        self.parent_id
    }

    pub fn cancel_token(&self) -> CancelToken {
        self.token.clone()
    }

    // =========================
    // Path B: Lifecycle Emission
    // =========================
    //
    // These methods are deterministic and safe:
    // - They emit to the canonical binary recorder IF it is initialized.
    // - They do NOT panic if the recorder is not initialized.
    // - They do NOT reorder events.
    //
    // Wiring into spawn/join runtime happens in Step 4 proper once we have those files.

    pub fn emit_task_started(&self) {
        if let Some(rec) = event_recorder::try_recorder() {
            if let Ok(mut r) = rec.lock() {
                let _ = r.record_task_started(self.task_id);
            }
        }
    }

    pub fn emit_task_finished(&self, exit_code: i32) {
        if let Some(rec) = event_recorder::try_recorder() {
            if let Ok(mut r) = rec.lock() {
                let _ = r.record_task_finished(self.task_id, exit_code);
            }
        }
    }

    pub fn emit_task_cancelled(&self, reason_code: u32) {
        if let Some(rec) = event_recorder::try_recorder() {
            if let Ok(mut r) = rec.lock() {
                let _ = r.record_task_cancelled(self.task_id, reason_code);
            }
        }
    }

    pub fn emit_task_joined(&self, joined_task: TaskId) {
        if let Some(rec) = event_recorder::try_recorder() {
            if let Ok(mut r) = rec.lock() {
                let _ = r.record_task_joined(self.task_id, joined_task);
            }
        }
    }

    // 🔐 capability allowed (keeps your existing JSONL/audit pipeline)
    pub fn emit_capability_allowed(&self, capability: &str, target: &str) {
        self.audit.emit(AuditEvent::CapabilityInvoked {
            task: self.task_id,
            capability: capability.to_string(),
            target: target.to_string(),
        });
    }

    // 🔐 capability denied (keeps your existing JSONL/audit pipeline)
    pub fn emit_capability_denied(&self, capability: &str, target: &str, reason: &str) {
        self.audit.emit(AuditEvent::ResourceViolation {
            task: self.task_id,
            kind: ResourceViolationKind::CapabilityDenied,
            detail: format!(
                "Denied capability={} target={} reason={}",
                capability, target, reason
            ),
        });
    }

    pub fn consume_fuel(&self, cost: Fuel) -> Result<(), FuelError> {
        if self.token.is_cancelled() {
            return Err(FuelError::Cancelled);
        }

        if cost == 0 {
            return Ok(());
        }

        let mut current = self.fuel_remaining.load(Ordering::Relaxed);
        loop {
            if current < cost {
                self.on_fuel_exhausted(cost, current);
                return Err(FuelError::Exhausted {
                    attempted_cost: cost,
                    remaining: current,
                });
            }

            let next = current - cost;
            match self.fuel_remaining.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn on_fuel_exhausted(&self, attempted_cost: Fuel, remaining: Fuel) {
        self.audit.emit(AuditEvent::ResourceViolation {
            task: self.task_id,
            kind: ResourceViolationKind::FuelExhausted,
            detail: format!(
                "Fuel exhausted: attempted_cost={}, remaining={}",
                attempted_cost, remaining
            ),
        });

        // Deterministic subtree cancellation + lifecycle emission.
        self.cancel_subtree_bfs_with_reason(self.task_id, CANCEL_REASON_FUEL_EXHAUSTED);
        self.token.cancel();
    }

    pub fn cancel_subtree_bfs(&self, root: TaskId) {
        self.cancel_subtree_bfs_with_reason(root, CANCEL_REASON_BFS_SUBTREE);
    }

    pub fn cancel_subtree_bfs_with_reason(&self, root: TaskId, reason_code: u32) {
        let mut q = VecDeque::new();
        q.push_back(root);

        while let Some(tid) = q.pop_front() {
            self.registry.mark_cancelled(tid);

            // cancel token
            let tok = self.registry.cancel_token_of(tid);
            tok.cancel();

            // emit lifecycle cancellation deterministically
            if let Some(rec) = event_recorder::try_recorder() {
                if let Ok(mut r) = rec.lock() {
                    let _ = r.record_task_cancelled(tid, reason_code);
                }
            }

            // BFS children
            let kids = self.registry.children_of(tid);
            for k in kids {
                q.push_back(k);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum FuelError {
    Cancelled,
    Exhausted {
        attempted_cost: Fuel,
        remaining: Fuel,
    },
}
