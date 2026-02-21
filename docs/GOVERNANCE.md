# NEX Governance Model

NEX is governed with a security-first philosophy.

This document defines decision-making structure.

---

# Maintainer Model

NEX follows a maintainer-led model.

Maintainers are responsible for:

- Reviewing contributions
- Preserving core invariants
- Approving RFCs
- Ensuring long-term language stability

---

# Core Invariants (Non-Negotiable)

The following principles cannot be compromised:

1. Deterministic execution
2. Capability-based authority
3. Explicit effect typing
4. Structured concurrency
5. Compile-time enforcement of policy

Any proposal violating these will be rejected.

---

# RFC-Based Evolution

Major language changes require:

1. Written RFC
2. Security analysis
3. Determinism impact assessment
4. Community discussion
5. Maintainer approval

---

# Decision Process

- Minor improvements: Maintainer approval
- Language semantics changes: RFC required
- Breaking changes: RFC + staged migration plan

---

# Long-Term Stability

NEX aims to become a foundation layer for secure autonomous systems.

Therefore:

- Stability is prioritized over rapid feature expansion
- Backward compatibility is respected where possible
- Security guarantees outweigh developer convenience

---

# Governance Philosophy

NEX is not feature-driven.

It is invariant-driven.

All evolution must strengthen:

- Static safety
- Predictability
- Authority boundaries
