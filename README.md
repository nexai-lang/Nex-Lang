NEX

A deterministic, capability-safe, effect-typed systems language.

Built from scratch as a secure execution substrate for autonomous agents.

This is not a toy DSL.
This is an experiment in building a language that refuses to execute unsafe behavior silently.

Current version: v0.3.9

---

## Why This Exists

Modern AI systems increasingly execute generated code.

That code:
- Reads files
- Opens sockets
- Spawns tasks
- Talks to networks

Most languages allow this implicitly.

NEX does not.

In NEX:
- Every side effect must be declared.
- Every capability must be granted.
- Every task must be accounted for.

No silent escalation.
No hidden IO.
No orphan tasks.

If the compiler cannot prove it is safe, it refuses to compile.

---

## Core Principles

1. Determinism over convenience
2. Explicit effects over hidden behavior
3. Capabilities over ambient authority
4. Compile-time guarantees over runtime hope

---

## Example

```nex
cap fs.read("logs/*.txt");

fn main() !io {
  let content = read_file("logs/a.txt");
  print(content);
}
```

If you attempt:

```nex
read_file("../secret.txt");
```

Compilation fails.

The language does not trust you.
And it definitely does not trust generated code.

---

## Network Capability

Static port enforcement:

```nex
cap net.listen(8000..9000);

fn main() !net {
  let p = 8085;
  listen_http(p);
}
```

Non-constant ports are rejected.
Dynamic escalation is rejected.

The compiler must be able to prove the port at compile time.

---

## Effect System

Functions must declare effects explicitly:

```
fn main() !io !net !async {
    ...
}
```

If you forget, compilation fails.

Effects are part of the function boundary.
Not an afterthought.

---

## Structured Concurrency

Tasks form a tree.

- No detached threads
- No forgotten handles
- No silent background execution

When the root exits, everything exits.

---

## What v0.3.9 Includes

- File capability glob matching
- Path traversal blocking
- Network port ranges
- Compile-time constant port verification
- Range + single port enforcement
- Deterministic effect validation
- Structured error rendering with spans

This version stabilizes the capability system.

---

## Status

This is an active research project.

It is being built incrementally toward:

v0.4.x → runtime governance
v0.5.x → modules
v1.0.0 → secure execution layer for NEXUS OS

---

## License

Apache-2.0
