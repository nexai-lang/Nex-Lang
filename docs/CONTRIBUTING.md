# Contributing to NEX

Thank you for your interest in contributing to NEX.

NEX is a deterministic, capability-safe systems language. Contributions must preserve its core invariants:

- Determinism
- Explicit authority
- Structured concurrency
- Compile-time enforcement

This document explains how to contribute safely.

---

# Core Philosophy

NEX is not a general-purpose language experiment.

It is an execution substrate for autonomous systems.

Every contribution must strengthen:

- Security guarantees
- Static validation
- Predictability of execution
- Clarity of semantics

---

# Development Setup

1. Clone the repository
2. Install Rust (stable toolchain)
3. Build:

```
cargo build
```

4. Run checks:

```
cargo run -- check examples/<file>.nex
```

---

# Contribution Types

We accept:

- Compiler bug fixes
- Diagnostic improvements
- Security strengthening
- Runtime invariant reinforcement
- Test coverage expansion
- Documentation improvements
- RFC proposals (for major changes)

We do NOT accept:

- Features that introduce implicit authority
- Hidden runtime behavior
- Non-deterministic execution semantics
- Unstructured concurrency

---

# Coding Standards

- Keep stages isolated (Lexer → Parser → AST → Checker → Codegen)
- Single responsibility per module
- No cross-stage leakage
- Explicit error spans
- No hidden state

---

# Pull Request Process

1. Open an issue or RFC for non-trivial changes
2. Write tests
3. Maintain deterministic behavior
4. Provide rationale for security impact
5. Submit PR to `main`

All changes are reviewed against NEX invariants.

---

# Design Changes

Major language changes require an RFC.

See: `docs/rfcs/0000-template.md`

---

# Security Issues

If you discover a security vulnerability:

- Do not open a public issue immediately
- Contact maintainers privately
- Provide reproduction details

---

# Final Principle

If a change weakens compile-time guarantees, it will not be accepted.

Security and determinism are structural.
