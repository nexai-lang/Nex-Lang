# NEX Architecture Overview

NEX is a deterministic, capability-safe, effect-typed systems language designed for secure autonomous execution.

The compiler follows a strict multi-stage pipeline. Each stage has a single responsibility and produces a validated intermediate form.

---

## Compilation Pipeline

````markdown
```mermaid
flowchart TD

    A["Source File .nex"]
    B["Lexer"]
    C["Parser"]
    D["Abstract Syntax Tree"]
    E["Semantic Checker"]
    F["Capability Validation"]
    G["Effect Enforcement"]
    H["Const Evaluation"]
    I["Structured Concurrency Validation"]
    J["Rust Code Generation"]
    K["Rust Compiler"]
    L["Executable Binary"]

    A --> B
    B --> C
    C --> D
    D --> E
    E --> F
    F --> G
    G --> H
    H --> I
    I --> J
    J --> K
    K --> L


---

## Stage Responsibilities

### 1. Lexer
Transforms raw source into tokens.
Deterministic and span-aware for precise diagnostics.

### 2. Parser
Builds a structured AST.
Ensures syntactic correctness before semantic analysis.

### 3. Semantic Checker
Validates:
- Type correctness
- Function signatures
- Deterministic return analysis
- Builtin function contracts

### 4. Capability Validation
Ensures:
- File access matches declared glob
- Network ports match declared range
- No implicit authority escalation

### 5. Effect Enforcement
Functions must explicitly declare:
- `!io`
- `!net`
- `!async`

Effects cannot be inferred implicitly across boundaries.

### 6. Const Evaluation
Statically evaluates:
- Integer expressions
- Const `let` bindings
- Trivial pure functions returning constants

This enables provable capability enforcement.

### 7. Structured Concurrency Validation
Guarantees:
- No detached tasks
- Deterministic parent-child cancellation
- Root task cleanup invariant

### 8. Rust Code Generation
Generates deterministic Rust code:
- Runtime guards mirror compile-time policy
- Capability allowlists embedded statically
- No dynamic authority acquisition

---

## Core Guarantees

NEX enforces at compile time:

• Explicit effect typing  
• Capability-based authority  
• Static validation of network ports  
• Path traversal blocking  
• Deterministic structured concurrency  
• No implicit runtime escalation  

Runtime checks mirror compile-time guarantees.

---

## Design Philosophy

NEX is built for environments where code may be generated dynamically (e.g., AI systems).

Security must be:

- Deterministic
- Verifiable
- Statistically provable before execution

NEX is designed as a secure execution substrate for autonomous systems.
