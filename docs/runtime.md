# NEX Runtime Architecture

NEX generates Rust backend code that enforces deterministic execution semantics.

The runtime is intentionally minimal.

---

# Runtime Goals

- Mirror compile-time guarantees
- Preserve determinism
- Enforce structured concurrency
- Prevent authority escalation
- Ensure safe program shutdown

---

# 1. Task Registry

The runtime maintains a parent-child task registry.

Properties:

- Each task has a parent
- The root task owns all descendants
- No task may detach
- All tasks must be joined or cancelled

This ensures no orphan threads remain.

---

# 2. Root Guard (RAII Cleanup)

A root guard ensures:

- Cancellation of remaining tasks at exit
- Deterministic join order
- No resource leakage
- Cleanup even during panic

This mirrors structured concurrency guarantees from the checker.

---

# 3. Capability Wrappers

Filesystem and network calls are wrapped.

The wrappers:

- Validate path normalization
- Enforce declared glob patterns
- Enforce declared port ranges
- Reject unauthorized access

These runtime checks exist as a defensive mirror of compile-time validation.

---

# 4. Effect-Aware Execution

The runtime scaffolding distinguishes:

- Pure functions
- `!io` functions
- `!async` functions

This ensures:

- Side effects occur only where declared
- Async execution remains structured
- Concurrency boundaries remain explicit

---

# 5. Deterministic Shutdown

Program exit guarantees:

1. Cancel remaining tasks
2. Join all children
3. Release resources
4. Exit cleanly

No background execution survives termination.

---

# Runtime Philosophy

The runtime does not add power.

It enforces constraints.

NEX is designed so that:

- The compiler prevents unsafe programs
- The runtime enforces invariant preservation
- The binary executes within declared authority

The runtime is a guardrail, not an engine.
