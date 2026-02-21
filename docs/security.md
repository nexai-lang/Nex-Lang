# NEX Security Model

NEX is designed as a capability-safe execution substrate for autonomous systems.

Security is not a runtime feature.
It is a compile-time invariant.

---

## Threat Model

NEX assumes:

- Code may be generated dynamically
- Code may be adversarial
- Code may attempt privilege escalation
- Code may attempt filesystem or network traversal
- Code may attempt detached concurrency

NEX enforces strict guarantees to eliminate these classes of risks.

---

# 1. Capability-Based Authority

NEX uses an explicit authority model.

No resource can be accessed unless declared.

Example:

```
cap fs.read("logs/*.txt");
cap net.listen(8000..9000);
```

If code attempts:

- Reading undeclared files
- Accessing out-of-range ports
- Traversing outside declared glob patterns

Compilation fails.

There is no runtime fallback.

---

# 2. No Implicit Authority

NEX does not allow:

- Dynamic capability construction
- Authority inference
- Implicit privilege inheritance
- Global ambient authority

All authority must be statically declared at the top level.

---

# 3. Effect System Enforcement

Functions must explicitly declare side effects.

Supported effects:

- `!io`
- `!async`

This prevents:

- Hidden I/O
- Silent mutation
- Undeclared asynchronous execution

Pure functions are statically enforced.

---

# 4. Structured Concurrency Guarantees

NEX enforces deterministic task trees.

Security properties:

- No detached tasks
- Parent-child task registry
- Subtree cancellation propagation
- No orphan background execution
- Root task cleanup at exit

This prevents:

- Zombie background threads
- Resource leaks
- Hidden asynchronous escalation

---

# 5. Compile-Time Policy Mirror

Every runtime policy mirrors a static rule.

If a program compiles:

- It cannot exceed its declared authority
- It cannot escalate privileges
- It cannot spawn unmanaged tasks

Runtime checks exist only to mirror compile-time guarantees.

---

# 6. Filesystem Safety

NEX enforces:

- Glob-based file access
- Path normalization
- Traversal blocking (`../` protection)
- Literal or const-folded path enforcement

Dynamic path computation is rejected.

---

# 7. Network Safety

NEX enforces:

- Literal or const-folded port values
- Range-based declarations
- No runtime port mutation

Example:

```
cap net.listen(8000..9000);
```

Listening on 7000 would fail compilation.

---

# Security Philosophy

Security is not an optional feature.

It is a property of the type system.

NEX assumes that autonomous systems must operate under strict authority boundaries.

The compiler is the first line of defense.
