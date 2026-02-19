# Changelog

## v0.1.0 (V1)
- Parser supports function parameters and multiple effects (`!io !async`)
- Type checker: builtin typing, arity, return propagation
- Effects enforcement: `print` → `!io`, async builtins → `!async`
- Capability system: `fs.read` + `net.listen` literal-only rules
- Rust codegen backend with safe main wrapper
- Root cancellation token + per-task token; `cancelled()` works globally
- Return analysis: void fallthrough allowed; non-void requires all paths return
- Golden regression test harness
