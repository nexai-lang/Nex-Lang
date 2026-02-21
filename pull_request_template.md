## Summary
What does this PR change?

## Why
Why is this change needed? Link issue/RFC if applicable.

## What Changed
- [ ] Lexer
- [ ] Parser
- [ ] AST
- [ ] Checker
- [ ] Codegen
- [ ] Runtime
- [ ] Docs / Tests

## Safety / Invariants Checklist
- [ ] Determinism preserved
- [ ] No ambient authority introduced
- [ ] Effects remain explicit at function boundary
- [ ] Capability checks remain compile-time enforced where possible
- [ ] Structured concurrency invariant preserved (no orphan tasks)

## Tests
Commands you ran:
```bash
cargo build
cargo test
cargo run -- check examples/<file>.nex

Notes

Anything reviewers should pay attention to (edge cases, follow-ups, etc.).


---

# 3) ✅ CI Pipeline (GitHub Actions)

## 3.1 Create workflow folder
Create: `.github/workflows/`

## 3.2 Add file: CI
Create: `.github/workflows/ci.yml`

Paste:

```yaml
name: CI

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

jobs:
  build-and-test:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Cache cargo
        uses: Swatinem/rust-cache@v2

      - name: Format (rustfmt)
        run: cargo fmt --all -- --check

      - name: Lint (clippy)
        run: cargo clippy --all-targets --all-features -- -D warnings

      - name: Build
        run: cargo build --verbose

      - name: Tests
        run: cargo test --verbose

      - name: Smoke check examples (if examples folder exists)
        run: |
          if [ -d "examples" ]; then
            for f in examples/*.nex; do
              [ -e "$f" ] || continue
              echo "Checking $f"
              cargo run -- check "$f"
            done
          fi
