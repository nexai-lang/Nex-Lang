//! v0.4.0 Phase 1 — Resource Governance Runtime Contract (thread runtime)
//!
//! Stable compiler↔runtime boundary:
//!   - TaskContext::consume_fuel(cost)
//!
//! Thread-based semantics:
//!   - Tasks are std::thread workers.
//!   - Cancellation is cooperative via Arc<AtomicBool>.
//!   - Fuel exhaustion cancels the entire subtree using BFS (non-recursive).
//!   - Joining is performed by root/shutdown logic *outside* registry locks.

use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

/// Stable identifier for tasks in the structured concurrency registry.
pub type TaskId = u64;

/// Bump only when you intentionally break the compiler↔runtime fuel contract.
pub const FUEL_API_VERSION: u32 = 1;

/// Fuel costs are abstract "steps" (compiler-defined), not time.
pub type Fuel = u64;

/// v0.3.9-style cancellation token: Arc<AtomicBool>.
/// Keep this simple and stable—this is part of the kernel ABI surface.
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

/// Audit events are machine-readable (JSONL-friendly).
/// Keep stable; replay/observability tooling will depend on this.
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
}

/// Sink abstraction: could write JSONL lines, store in memory, forward to parent, etc.
pub trait AuditSink: Send + Sync + 'static {
    fn emit(&self, event: AuditEvent);
}

/// Registry interface required for BFS cancellation.
/// IMPORTANT: Joining must happen outside registry locks; this trait provides only snapshots/signals.
pub trait TaskRegistry: Send + Sync + 'static {
    /// Snapshot of direct children of `task`.
    fn children_of(&self, task: TaskId) -> Vec<TaskId>;

    /// Mark cancelled in registry state (optional but useful).
    fn mark_cancelled(&self, task: TaskId);

    /// Get the cancel token for a task.
    fn cancel_token_of(&self, task: TaskId) -> CancelToken;
}

/// Per-task resource governance context.
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

    #[inline]
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    #[inline]
    pub fn parent_id(&self) -> Option<TaskId> {
        self.parent_id
    }

    #[inline]
    pub fn fuel_api_version(&self) -> u32 {
        self.fuel_api_version
    }

    #[inline]
    pub fn fuel_remaining(&self) -> Fuel {
        self.fuel_remaining.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn cancel_token(&self) -> CancelToken {
        self.token.clone()
    }

    /// Compiler-injected checkpoint.
    ///
    /// Semantics:
    /// - If task already cancelled → Err(Cancelled) (fast path).
    /// - Else atomically subtract cost from remaining fuel.
    /// - If insufficient fuel → emit audit, BFS-cancel subtree, cancel self, Err(Exhausted).
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
        // Audit best-effort (do not panic here).
        self.audit.emit(AuditEvent::ResourceViolation {
            task: self.task_id,
            kind: ResourceViolationKind::FuelExhausted,
            detail: format!(
                "Fuel exhausted: attempted_cost={}, remaining={}",
                attempted_cost, remaining
            ),
        });

        // Cancel subtree iteratively (BFS).
        self.cancel_subtree_bfs(self.task_id);

        // Also cancel local token for fast exit on subsequent checkpoints.
        self.token.cancel();
    }

    /// BFS subtree cancellation to avoid recursion depth attacks.
    ///
    /// This only signals cancellation; join/shutdown logic must still join deterministically.
    pub fn cancel_subtree_bfs(&self, root: TaskId) {
        let mut q = VecDeque::new();
        q.push_back(root);

        while let Some(tid) = q.pop_front() {
            self.registry.mark_cancelled(tid);

            let tok = self.registry.cancel_token_of(tid);
            tok.cancel();

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
