# NEX

> A deterministic, capability-safe, effect-typed systems language  
> designed as a secure execution substrate for autonomous agents.

---

## Problem

Modern AI systems increasingly execute:

- Dynamically generated code
- Untrusted tools
- File system operations
- Network operations
- Concurrent tasks

Most general-purpose languages provide:

- Unrestricted filesystem access
- Unrestricted networking
- No enforced effect boundaries
- Ad-hoc async cancellation
- No deterministic task structure

This creates security, correctness, and isolation risks.

---

## Design Goals

NEX is designed to provide:

1. Compile-time capability enforcement
2. Explicit effect declarations
3. Deterministic structured concurrency
4. Runtime enforcement mirroring compile-time policy
5. Memory-safe execution via Rust backend

NEX is not a scripting language.

It is a policy-enforced execution substrate.

---

## Core Principles

- No implicit side effects
- No detached async execution
- All I/O must be declared
- All async must be declared
- Capabilities must be explicitly granted
- Parent-child task trees are enforced
- Cancellation propagates deterministically

---

## Example

```nex
cap fs.read("config.txt");

fn worker() !async {
    spawn {
        if cancelled() {
            return;
        }
    };
}

fn main() !async {
    let t = spawn { worker(); };
    cancel(t);
    join(t);
}
```

---

## Structured Concurrency (v0.2.0)

- Every `spawn` is attached to a parent task
- Cancellation propagates to descendants
- `join` waits for entire subtree
- Parent exit triggers deterministic child cleanup
- No orphaned tasks possible

---

## Compilation Pipeline

Lexer → Parser → AST → Checker → Rust Codegen

---

## Roadmap

- v0.2.0 — Structured concurrency (complete)
- v0.3.0 — Capability patterns
- v0.4.0 — Runtime limits
- v0.5.0 — Module system
- v1.0.0 — Stable execution kernel for autonomous systems


Improve README for professional positioning
