# Security Policy

NEX is a governed execution language and runtime designed to constrain authority by construction. Security is a core product requirement, not an optional feature.

This document describes how to report vulnerabilities and what security expectations users should have at the current stage of the project.

---

## Supported Versions

NEX is currently **experimental**. Security fixes will be released on the latest active version line.

| Version | Supported |
|--------:|:---------:|
| v0.4.x  | ✅ Yes |
| v0.3.x  | ⚠️ Best-effort |
| < v0.3  | ❌ No |

---

## Security Model (High Level)

NEX aims to provide the following guarantees:

- **Deny-by-default capabilities**: filesystem/network operations require explicit capability declarations.
- **Effect transparency**: `!io` and `!async` must be declared at function boundaries; transitive effects are checked.
- **Structured concurrency**: task trees are enforced; cancellation is deterministic; no orphan tasks at process exit.
- **Resource governance**: cooperative fuel checkpoints and memory ceilings provide bounded execution.
- **Audit telemetry**: runtime emits machine-readable JSONL events for security-relevant actions.

NEX is not a general sandbox and does not attempt to defend against all OS-level side channels. Its purpose is to provide a reliable, deterministic control layer for autonomous execution.

---

## Reporting a Vulnerability

If you believe you have found a security vulnerability, please report it responsibly.

### Preferred reporting method

1. Open a **GitHub Issue** titled:  
   **`[SECURITY] <short description>`**
2. Include:
   - NEX version (`./target/debug/nex --version` if available, or tag/commit hash)
   - Platform (Linux/Windows/macOS)
   - Minimal reproduction (`.nex` program if possible)
   - Expected vs actual behavior
   - Any logs (including `nex_audit.jsonl` output if relevant)

### If you need private disclosure

If you are uncomfortable filing a public issue:
- Create a draft issue with minimal detail and request private coordination.

(As the project matures, a dedicated security contact and formal CVE handling may be added.)

---

## What Counts as a Security Issue

We consider the following in-scope:

- Capability bypass (e.g., path traversal, glob bypass, normalization failures)
- Effect enforcement bypass (`!io`, `!async` not required when it should be)
- Escaping structured concurrency invariants (orphan tasks, cancel/join bypass)
- Resource governance bypass (fuel/memory limits not enforced as specified)
- Audit log integrity issues (missing or incorrect security-relevant events)
- Crashes or panics that can be triggered by untrusted input (compiler or runtime)

Out of scope (for now):

- OS kernel vulnerabilities
- Hardware side channels
- Attacks requiring local administrator privileges

---

## Security Response Process

When a report is accepted:

1. **Triage** within a reasonable timeframe
2. **Reproduce** and classify severity
3. **Patch** with regression tests (golden tests preferred)
4. **Release** a tagged version with clear changelog notes

---

## Hardening Roadmap

Planned improvements include:

- Stable IR layers (HIR/MIR) with stronger validation boundaries
- Deterministic replay tooling for incident analysis
- Stronger memory accounting and per-task hard ceilings
- Expanded audit schema and event sequencing guarantees
- Tool ecosystem governance (safe web/search adapters)

---

## Acknowledgements

<<<<<<< HEAD
Security contributions are welcome. If you submit a report or patch, you may be credited in the changelog/release notes (at your preference).
=======
Security contributions are welcome. If you submit a report or patch, you may be credited in the changelog/release notes (at your preference).
>>>>>>> 0f63f2a (docs: add architecture animation and update README)
