```markdown
# NEX

A deterministic, capability-safe, effect-typed systems language  
for governed autonomous execution.

---

## Overview

NEX is an experimental execution language designed as a secure substrate for autonomous agents.

It is not:
- A scripting DSL
- A general-purpose language
- A replacement for Rust

NEX explores one central question:

> Can an execution environment refuse unsafe behavior by construction?

The language enforces:

- Explicit effect typing
- Deny-by-default capability security
- Structured concurrency
- Deterministic cancellation
- Bounded resource governance
- Machine-readable audit telemetry

---

## Design Principles

### 1. Determinism Over Convenience

No silent failure.  
No implicit capability escalation.  
All side effects must be declared.

---

### 2. Capability Security (Deny-by-Default)

```nex
cap fs.read("examples/*.nex");
```

Generated programs cannot exceed declared authority.

---

### 3. Effect Typing

```nex
fn main !async { }
fn main !io { }
```

Transitive effect checking prevents hidden behavior.

---

### 4. Structured Concurrency

Tasks form strict parent–child trees.  
No orphan threads.  
No detached background work.

---

### 5. Governed Execution

Execution is bounded by:

- Cooperative fuel checkpoints
- Memory ceilings
- Deterministic cancellation
- JSONL audit logging

NEX behaves as a bounded execution kernel.

---

## Current Version

### v0.4.3 — Governed Execution Kernel

This version includes:

- Cooperative Fuel Model
- Memory Governance
- JSONL Audit Telemetry
- BFS Subtree Cancellation
- No-Orphan Task Enforcement
- `NEX_OUT_DIR` isolated per-run build directories
- Deterministic golden test suite (fully green)

---

## Architecture

NEX follows a deterministic compilation pipeline:

```mermaid
flowchart TD
    A[.nex Source File] --> B[Lexer]
    B --> C[Parser]
    C --> D[AST Construction]
    D --> E[Semantic Checker]
    E --> F[Capability Validation]
    F --> G[Effect Enforcement]
    G --> H[Rust Code Generation]
    H --> I[Rust Compilation]
    I --> J[Governed Executable]
```

---

## Runtime Model

Generated programs include:

- Atomic cancellation tokens
- Deterministic join ordering
- Resource governance hooks
- Structured task registry
- JSON machine-readable audit logs

All violations are recorded deterministically.

---

## Example

### Structured Concurrency

```nex
fn main !async {
    spawn {
        print("child running");
    }
}
```

### Explicit Capability Declaration

```nex
cap fs.read("examples/*.nex");

fn main !io {
    let content = read_file("examples/demo.nex");
    print(content);
}
```

---

## Running

```bash
cargo build
./target/debug/nex check examples/demo.nex
./target/debug/nex run examples/demo.nex
```

---

## Isolated Builds

```bash
NEX_OUT_DIR=target/run_1 ./target/debug/nex run examples/demo.nex
```

---

## Resource Budgets

```bash
NEX_FUEL_BUDGET=1000
NEX_MEM_BUDGET=1024
NEX_AUDIT_PATH=audit.jsonl
```

---

## Security Model

NEX enforces authority at compile-time and runtime:

- Capabilities must be declared explicitly
- Effects must be declared at function boundaries
- Network ports must be statically provable
- File access must match declared glob patterns
- No detached tasks (structured concurrency invariant)

The compiler guarantees that generated programs cannot exceed declared authority.

---

## Roadmap

### v0.5.x — Observability & Replay
- Run envelope events
- Event sequencing
- Deterministic replay harness

### v0.6.x — Stable IR & Tool Ecosystem
- Stable HIR/MIR
- Safe web/search tools

### v0.7.x — Multi-Agent Execution
- Swarm governance
- Verified self-improvement boundaries

### v1.0 — Production-Grade Governed Kernel

---

## Status

NEX is experimental.

It is a research-driven systems exploration into safe autonomous execution.

---

---

## License

Apache-2.0
# Compiler Architecture

NEX follows a deterministic, multi-stage compilation pipeline.


---

## Security Model

NEX enforces authority at compile time:

• Capabilities must be declared explicitly  
• Effects must be declared at function boundaries  
• Network ports must be statically provable  
• File access must match declared glob patterns  
• No detached tasks (structured concurrency invariant)

The compiler guarantees that generated programs cannot exceed declared authority.

---

## Documentation

- [Architecture](docs/architecture.md)
- [Runtime Model](docs/runtime.md)
- [Security Model](docs/security.md)
- [Language Specification](docs/spec.md)
- [Versioning Policy](docs/versioning.md)
- [Roadmap](docs/roadmap.md)
- [Design Principles](docs/DESIGN.md)
- [Governance](docs/GOVERNANCE.md)
- [Contributing Guide](docs/CONTRIBUTING.md)
- [RFC Process](docs/rfcs/0000-template.md)

---

![Version](https://img.shields.io/badge/version-0.3.9-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Status](https://img.shields.io/badge/status-experimental-orange)

