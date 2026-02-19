# NEX

**Capability-safe, effect-typed programming language for secure autonomous systems.**

NEX is an experimental AI-native language designed to enforce **capability safety** and **effect declarations** at compile-time and runtime.

It is built for a future where autonomous agents execute code, access files, spawn tasks, and interact with networks — without unrestricted system access.

---

## Why NEX?

Modern AI systems frequently execute untrusted tools or dynamically generated code.

Most programming languages provide:
- Full file access
- Full network access
- No enforced effect boundaries

NEX introduces:

- 🔒 **Capability-based IO control**
- ⚡ **Effect-typed functions (`!io`, `!async`)**
- 🧠 **Deterministic return analysis**
- 🔁 **Root cancellation tokens**
- 🧵 **Async task primitives (`spawn`, `join`, `cancel`)**
- 🦀 **Rust backend for safe execution**

---

## Example

```nex
cap fs.read("allowed.txt");

fn main() !io {
  let x = read_file("allowed.txt");
  print(x);
}
