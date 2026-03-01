# Soundness Envelope (v1.0.0-RC2)

## Scope

This document defines the deterministic compiler/runtime boundary for NEX.

The envelope is conservative:
- Static checks MAY reject safe programs.
- Static checks MUST NOT claim runtime properties they cannot prove.
- Runtime evidence remains the final authority for execution outcomes.

## Static-Proven (Compile Time)

The compiler enforces these properties deterministically:

1. IR structure validity
- HIR and MIR decoding are fail-closed and version-gated.
- Malformed IR bytes are rejected without panic.

2. MIR checker invariants
- Presence of `main` entrypoint.
- Effect declaration coverage for the checker's known effect surface (`!io`, `!net`, `!async`) using deterministic transitive analysis.
- Deterministic MIR type/effect diagnostics with stable error codes.
- Control-flow structural checks (valid branch/jump targets).

3. Governance static analyses
- Determinism boundary facts and strict-mode rejection (when enabled).
- Capability-flow declaration checks.
- Message schema declaration/use consistency checks.
- Cost-policy checks (upper-bound static model + policy gates).
- Deadlock-risk approximation warnings/policy gating.

4. Static artifacts
- GovernanceFacts and CostFacts are canonically serialized with fixed headers/versions and deterministic ordering.

## Runtime-Enforced (Execution Time)

The runtime is authoritative for dynamic properties:

1. Capability decisions
- IO-proxy and bus allow/deny outcomes, limits, and debit failures.

2. Fuel and scheduling
- Actual fuel exhaustion, scheduling interleavings, and cancellation behavior.

3. Deadlock ground truth
- Runtime deadlock detection events are authoritative for observed execution deadlocks.
- Static deadlock analysis is risk-only and not a proof of deadlock.

4. Replay/evidence
- Evidence signatures, run hash chaining, bundle verification, and replay acceptance (`✅ REPLAY OK`) are runtime-log grounded.

## Non-Goals (Not Statistically Proven)

The compiler does not prove:
- Liveness/progress for all programs.
- Global deadlock freedom.
- Full semantic equivalence of all lowered representations.
- Correctness of external systems (filesystems, networks, kernels, hardware).

## Determinism Requirements

All diagnostics and artifacts in this envelope are deterministic:
- No wall-clock data in compiler outputs.
- No randomized ordering in compiler outputs.
- Stable traversal/serialization order for all reported facts and diagnostics.

## Versioning Contract

Envelope interpretation is versioned by:
- IR version headers (HIR/MIR/canonical facts formats).
- GovernanceFacts hash embedded into policy/evidence pathways.

Unsupported versions MUST fail closed with deterministic errors.
