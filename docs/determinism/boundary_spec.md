# Determinism Boundary Specification (v0.9.2)

Status: Normative

This document defines the determinism boundary for NEX compilation and strict
mode enforcement.

## 1. Deterministic Execution Contract

A program is deterministic only if all observable behavior is reproducible for
identical source and identical recorded inputs.

The compiler and runtime MUST avoid wall-clock sources, random sources, and
nondeterministic ordering at this boundary.

## 2. Forbidden Sources Under Strict Determinism

When strict determinism is enabled (`--strict-determinism`), the compiler MUST
reject programs that contain any of these sources:

1. Wall-clock or time-dependent calls.
2. Randomness / RNG calls.
3. IO proxy dependent operations.
4. Network operations.
5. Agent bus operations.
6. Spawn-based concurrency primitives.
7. Floating-point nondeterminism markers (conservative approximation).

## 3. Whole-Program Facts

HIR analysis computes deterministic whole-program facts:

- `uses_time`
- `uses_rng`
- `uses_io_proxy`
- `uses_net`
- `uses_bus`
- `uses_spawn`
- `uses_float_nondet`

The analysis is conservative by design (sound over complete): false positives
are allowed; false negatives are not acceptable for known boundary constructs.

## 4. Diagnostics Requirements

Strict mode diagnostics MUST be deterministic:

- deterministic violation priority order,
- deterministic wording,
- deterministic span selection,
- no dependence on wall-clock or unstable map iteration.

## 5. Non-goals

This boundary spec does not attempt to prove semantic equivalence across
hardware floating-point implementations. `uses_float_nondet` is a conservative
marker intended to prevent accidental acceptance in strict mode.
