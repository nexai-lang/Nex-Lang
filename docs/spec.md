# NEX Language Specification (Draft)

**Status:** Draft (pre-1.0)  
This document defines the intended semantics of NEX as they stabilize.

---

## 1. Goals

NEX is designed for:
- Deterministic execution
- Explicit authority (capabilities)
- Explicit effects
- Structured concurrency as a program invariant
- Static enforcement with runtime mirroring

Non-goals:
- Implicit I/O or ambient authority
- Detached / untracked async work
- Nondeterministic semantics

---

## 2. Compilation Model

Pipeline:
1. Lexer: source → tokens (with spans)
2. Parser: tokens → AST
3. Checker: validates semantics + effects + capabilities + concurrency invariants
4. Codegen: emits Rust with runtime policy enforcement
5. Rust compiler: produces binary

---

## 3. Effects

Effects are declared at function boundary:
- `!io` required for filesystem operations
- `!net` required for network operations (if used in your version)
- `!async` required for concurrency primitives (spawn/join/cancel/cancelled)

Rule:
> If a function may cause an effect, that effect must appear in its signature.

---

## 4. Capabilities (Authority)

Capabilities are explicit declarations of authority, for example:
- `cap fs.read("logs/*.txt");`
- `cap net.listen(8000..9000);`

Rules:
- No operation may exceed declared authority
- Checker must reject operations that cannot be proven within caps
- Runtime must enforce the same policy

---

## 5. Structured Concurrency

Invariant:
- All tasks form a tree rooted at the root task
- No orphan tasks at process exit
- Cancellation propagates down the tree
- Joining is deterministic and safe

---

## 6. Determinism

NEX programs must behave predictably under the same inputs:
- No hidden concurrency
- No implicit IO
- No capability inference

---

## 7. Diagnostics

All errors should be:
- precise (span-aware)
- actionable (cause + hint)
- deterministic (stable ordering)

---

## 8. Appendix: Examples

### Capability + IO
```nex
cap fs.read("logs/*.txt");

fn main() !io {
  let x = fs.read("logs/a.txt");
  print(x);
}

Net listen range + const port

cap net.listen(8000..9000);

fn main() !net !async {
  let p = 8000 + 85;
  net.listen(p);
}


---

# ✅ Step 7 — Commit your changes on GitHub UI
In the web editor:
1. After adding files, you’ll see a list of changes.
2. Write commit message:
   - `Add community health files (templates, CI, security, docs)`
3. Click **Commit** (commit directly to `main` is fine for now).

---

# ✅ Step 8 — Confirm it works
After commit:
- Go to **Actions** tab → you should see CI running.
- Go to **Issues → New issue** → template chooser should appear.
- Open a PR (even a test PR) → PR template should appear.

---

## Next: Professional polish (optional but high impact)
Once these are in, the next *attention-getter* step is:
- Add badges to README (CI status, license, latest tag)
- Add `CODE_OF_CONDUCT.md` (optional)
- Add `docs/` index page linking to security/runtime/spec/versioning
