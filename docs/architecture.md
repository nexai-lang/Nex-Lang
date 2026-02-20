# NEX Architecture Overview

NEX follows a deterministic multi-stage compilation pipeline:

Lexer → Parser → AST → Checker → Rust Codegen

## Core Guarantees

- Explicit effect typing
- Capability-based I/O control
- Deterministic structured concurrency
- Compile-time policy enforcement
- Runtime enforcement mirroring compile-time model

NEX is designed as an execution substrate for autonomous systems,
where security, determinism, and isolation are first-class properties.
