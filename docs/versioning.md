# Versioning Policy

NEX follows Semantic Versioning.

Format:

MAJOR.MINOR.PATCH

Example:
0.3.9

---

## MAJOR

Incremented when:
- Breaking language syntax changes
- AST structure changes
- Compiler behavior changes that invalidate existing programs

---

## MINOR

Incremented when:
- New language features are added
- New capabilities are introduced
- Structured concurrency enhancements
- Backwards-compatible compiler improvements

---

## PATCH

Incremented when:
- Bug fixes
- Diagnostic improvements
- Performance improvements
- Internal refactors with no language impact

---

## Pre-1.0 Policy

Until v1.0.0:

Minor versions MAY contain breaking changes.

After v1.0.0:

Breaking changes require MAJOR version increment.

---

## Stability Targets

- v0.x → Experimental but structured
- v1.0.0 → Stable core language
- v1.x → Production compiler evolution
