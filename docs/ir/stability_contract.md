# IR Stability Contract (Skeleton)

Status: Normative skeleton for v0.9.0.

## 1. Scope

This document defines the compatibility contract for NEX intermediate representations (IRs).

For v0.9.0, only a High-level IR (HIR) contract scaffold is active. MIR is reserved.

## 2. Version Constants

Compiler/runtime components MUST expose IR version constants:

- `HIR_VERSION`
- `MIR_VERSION`

v0.9.0 baseline values:

- `HIR_VERSION = 1`
- `MIR_VERSION = 0` (placeholder)

## 3. Compatibility Policy

A consumer MUST reject IR produced with a version it does not explicitly support.

Compatibility classes:

- Major/identity compatibility: same exact version value.
- Forward compatibility: not guaranteed unless explicitly documented.
- Backward compatibility: not guaranteed unless explicitly documented.

v0.9.0 policy:

- HIR: exact-version match only.
- MIR: placeholder, no compatibility guarantees.

## 4. Canonical Ownership

HIR is the canonical home for governance facts extracted during lowering.

At minimum, the HIR payload MUST carry deterministic governance facts for:

- declared capabilities
- declared neural model references

Additional governance facts MAY be added in future versions under explicit version bumps.

## 5. Canonical Serialization (Placeholder)

A canonical serialization format will be defined in a future revision.

Until then:

- Implementations SHOULD keep lowering deterministic.
- Implementations MUST avoid non-deterministic fields in IR payloads.

## 6. Determinism Requirements

Implementations MUST NOT include wall-clock timestamps, random values, or host-variant ordering in canonical IR representations.

Collections with semantic ordering requirements MUST use deterministic ordering.

## 7. Future Work

Pending sections for full contract ratification:

- Canonical HIR schema reference
- MIR schema and ownership boundaries
- Canonical byte serialization format
- Upgrade/downgrade translation rules
