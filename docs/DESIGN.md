# NEX Design Principles

NEX is designed as a deterministic execution language for autonomous systems.

This document outlines architectural design choices.

---

# 1. Multi-Stage Compilation

NEX follows a strict pipeline:

Lexer → Parser → AST → Semantic Checker → Validation → Codegen

Each stage:

- Has a single responsibility
- Produces a validated intermediate form
- Does not depend on downstream behavior

This prevents cross-layer ambiguity.

---

# 2. Explicit Authority

NEX rejects ambient authority.

Resources must be declared:

```
cap fs.read("logs/*.txt");
cap net.listen(8000..9000);
```

Authority is not inferred.

---

# 3. Effect Typing

Functions declare side effects:

- `!io`
- `!async`

Pure functions remain pure by construction.

This makes execution reasoning mechanical.

---

# 4. Deterministic Concurrency

NEX enforces structured concurrency:

- No detached tasks
- Deterministic cancellation trees
- Parent-child registry
- Guaranteed cleanup

Concurrency must form a tree, not a graph.

---

# 5. Compile-Time First

If an error can be detected at compile-time, it must be.

Runtime checks mirror static guarantees.

---

# 6. AI-Ready Execution Model

NEX assumes code may be:

- Generated dynamically
- Produced by autonomous systems
- Executed in high-risk environments

Therefore:

- Authority boundaries are explicit
- Execution is predictable
- Policy enforcement is structural

---

# Design Philosophy

NEX is not designed for convenience.

It is designed for correctness.

Security, determinism, and isolation are first-class properties.
