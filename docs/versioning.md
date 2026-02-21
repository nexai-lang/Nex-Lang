# NEX Versioning Strategy

NEX uses semantic versioning with an explicit rule:
**minor versions may add features; patch versions may only fix bugs.**

Example: `v0.3.9`

> While NEX is < 1.0, breaking changes may occur, but we still document them as if we were post-1.0.

## Version Meaning
- **MAJOR**: Reserved for v1.0 when core language semantics stabilize.
- **MINOR**: Feature milestones (language semantics, checker rules, runtime invariants).
- **PATCH**: Bug fixes, diagnostics, docs, tests, performance improvements that do not change semantics.

## Release Requirements
A release tag must include:
- Release notes summarizing changes
- Tests passing in CI
- Any breaking change clearly highlighted

## Tagging
- Tags use `vX.Y.Z` format (e.g., `v0.3.9`)
- `main` is always ahead of the last tag
- Work-in-progress features should land behind tests/examples and be documented

## Compatibility Notes
Each MINOR release should state:
- Syntax additions/changes
- Checker rule changes
- Runtime enforcement changes
- Migration hints for existing `.nex` examples

